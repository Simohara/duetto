//! Real loopback integration of the production media scheduler. No pairing,
//! physical capture device, HomePod or application audio is used here.
use crate::{
    SharedAudio,
    playback_clock::{PACKET_FRAMES, PlaybackClock, SharedStart},
};
use cidermill_airplay::{
    ControlChannel, OsRng, Protocol, Request, Response, SenderConnection,
    audio::{AudioSendConfig, StreamFormat, StreamType, TimingMode},
    plist::{Dictionary, Value},
    receiver::{AudioStreamFormat, RealtimeReceiver},
    rtsp::Decoder,
};
use std::{
    collections::VecDeque,
    io::{Read, Write},
    net::{Ipv4Addr, TcpListener, TcpStream, UdpSocket},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

#[derive(Default, Debug)]
struct Observed {
    sequences: Vec<u16>,
    timestamps: Vec<u32>,
    syncs: usize,
    volume_while_feedback_pending: bool,
    // Audio/sync progress while a particular feedback was held for >1s.
    stalled_windows: Vec<(usize, usize)>,
    first_audio_sync_age: Option<f64>,
    pcm_packets: usize,
}

fn setup_response(request: &Request, data_port: u16, control_port: u16) -> Response {
    let mut stream = Dictionary::new();
    stream.insert(
        "dataPort".into(),
        Value::Integer(u64::from(data_port).into()),
    );
    stream.insert(
        "controlPort".into(),
        Value::Integer(u64::from(control_port).into()),
    );
    let mut body = Dictionary::new();
    body.insert(
        "streams".into(),
        Value::Array(vec![Value::Dictionary(stream)]),
    );
    let mut bytes = Vec::new();
    Value::Dictionary(body)
        .to_writer_binary(&mut bytes)
        .unwrap();
    let mut response = Response::new(Protocol::Rtsp, 200, "OK", bytes);
    response
        .headers
        .set("CSeq", request.headers.get("CSeq").unwrap());
    response
}

fn mock_receiver(
    mut tcp: TcpStream,
    data: UdpSocket,
    control: UdpSocket,
    index: usize,
    startup_delay: Duration,
    received: Arc<AtomicUsize>,
    finish: mpsc::Receiver<()>,
) -> Observed {
    tcp.set_nonblocking(true).unwrap();
    data.set_nonblocking(true).unwrap();
    control.set_nonblocking(true).unwrap();
    let mut decoder = Decoder::new();
    let mut observed = Observed::default();
    let mut feedback = VecDeque::new();
    let mut latest_sync_ntp = None;
    let mut first_audio_ntp = None;
    let mut audio = RealtimeReceiver::new(
        [index as u8 + 1; 32],
        AudioStreamFormat::new(1, 0x800, 44100, PACKET_FRAMES),
    )
    .unwrap();
    let delay = Duration::from_millis(1200 + index as u64 * 400);
    let mut writes: VecDeque<(Vec<u8>, usize)> = VecDeque::new();
    let started = Instant::now();
    loop {
        if finish.try_recv().is_ok() {
            return observed;
        }
        assert!(
            started.elapsed() < Duration::from_secs(15),
            "receiver test timed out"
        );
        let mut buffer = [0u8; 8192];
        loop {
            match data.recv(&mut buffer) {
                Ok(size) => {
                    if observed.sequences.is_empty() {
                        let now = cidermill_airplay::NtpTimestamp::now().to_bits();
                        first_audio_ntp = Some(now);
                        observed.first_audio_sync_age = latest_sync_ntp
                            .map(|ntp: u64| now.wrapping_sub(ntp) as i64 as f64 / 4_294_967_296.0);
                    }
                    assert!(
                        size > 12 + 16,
                        "must be packetizer's encrypted RTP, not plain marker data"
                    );
                    observed
                        .sequences
                        .push(u16::from_be_bytes(buffer[2..4].try_into().unwrap()));
                    observed
                        .timestamps
                        .push(u32::from_be_bytes(buffer[4..8].try_into().unwrap()));
                    audio
                        .on_data(&buffer[..size])
                        .expect("RTP must decrypt with the negotiated per-session key");
                    while let Some(pcm) = audio.next_pcm().unwrap() {
                        let value = observed.pcm_packets as i16 + 1;
                        let expected = if index == 0 { value } else { -value };
                        assert!(!pcm.concealed);
                        assert!(
                            pcm.samples.iter().all(|sample| *sample == expected),
                            "each speaker must receive its routed, nonzero PCM, not just valid RTP headers"
                        );
                        observed.pcm_packets += 1;
                    }
                    received.store(observed.sequences.len(), Ordering::Release);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("UDP data receive: {error}"),
            }
        }
        loop {
            match control.recv(&mut buffer) {
                Ok(size) => {
                    assert_eq!(size, 20);
                    latest_sync_ntp = Some(u64::from_be_bytes(buffer[8..16].try_into().unwrap()));
                    // UDP sockets can be polled in either order even though
                    // the sender sends its initial sync before the first RTP.
                    if observed.first_audio_sync_age.is_none() {
                        observed.first_audio_sync_age = first_audio_ntp.map(|received: u64| {
                            received.wrapping_sub(latest_sync_ntp.unwrap()) as i64 as f64
                                / 4_294_967_296.0
                        });
                    }
                    observed.syncs += 1;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("UDP sync receive: {error}"),
            }
        }
        match tcp.read(&mut buffer) {
            Ok(0) => return observed,
            Ok(size) => decoder.push(&buffer[..size]),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => panic!("RTSP receive: {error}"),
        }
        while let Some(request) = decoder.next_request().unwrap() {
            if request.method == "RECORD" {
                // One device finishes startup much later than its peer.
                thread::sleep(startup_delay);
            }
            if request.uri == "/feedback" {
                let mut response = Response::new(Protocol::Rtsp, 200, "OK", vec![]);
                response
                    .headers
                    .set("CSeq", request.headers.get("CSeq").unwrap());
                feedback.push_back((
                    Instant::now() + delay,
                    response.encode(),
                    observed.sequences.len(),
                    observed.syncs,
                ));
                continue;
            }
            if request.method == "SET_PARAMETER" && !feedback.is_empty() {
                observed.volume_while_feedback_pending = true;
            }
            let response = if request.method == "SETUP" {
                setup_response(
                    &request,
                    data.local_addr().unwrap().port(),
                    control.local_addr().unwrap().port(),
                )
            } else {
                let mut response = Response::new(Protocol::Rtsp, 200, "OK", vec![]);
                response
                    .headers
                    .set("CSeq", request.headers.get("CSeq").unwrap());
                response
            };
            writes.push_back((response.encode(), 0));
        }
        while feedback
            .front()
            .is_some_and(|(due, _, _, _)| Instant::now() >= *due)
        {
            let (_, bytes, old_audio, old_sync) = feedback.pop_front().unwrap();
            observed.stalled_windows.push((
                observed.sequences.len() - old_audio,
                observed.syncs - old_sync,
            ));
            writes.push_back((bytes, 0));
        }
        while let Some((bytes, offset)) = writes.front_mut() {
            match tcp.write(&bytes[*offset..]) {
                Ok(0) => panic!("RTSP write returned zero"),
                Ok(size) => {
                    *offset += size;
                    if *offset == bytes.len() {
                        writes.pop_front();
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("RTSP reply: {error}"),
            }
        }
        thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn two_production_sessions_keep_audio_and_sync_running_during_slow_feedback() {
    exercise_sessions(false);
}

#[test]
fn unequal_startup_and_capture_burst_keep_both_routes_fresh_and_drain_without_repacing() {
    exercise_sessions(true);
}

fn exercise_sessions(startup_burst: bool) {
    // Includes the second feedback completion at 1.6 + 2.0 + 1.6 seconds.
    // Stay below the OS UDP receive buffer so the test measures the sender's
    // pacing rather than artificial loopback packet loss.
    let packets = if startup_burst { 32 } else { 750 };
    let stop = Arc::new(AtomicBool::new(false));
    let shared_clock = Arc::new(SharedStart::new());
    let primed = Arc::new(AtomicBool::new(false));
    let (ready_tx, ready_rx) = mpsc::channel();
    let mut sources = Vec::new();
    let mut sessions = Vec::new();
    let mut servers = Vec::new();
    let mut counters = Vec::new();
    let mut volumes = Vec::new();
    for index in 0..2 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        let receive_data = UdpSocket::bind("127.0.0.1:0").unwrap();
        let receive_control = UdpSocket::bind("127.0.0.1:0").unwrap();
        let counter = Arc::new(AtomicUsize::new(0));
        counters.push(counter.clone());
        let (finish, finished) = mpsc::channel();
        let receiver = thread::spawn(move || {
            mock_receiver(
                server,
                receive_data,
                receive_control,
                index,
                if startup_burst && index == 1 {
                    Duration::from_millis(1800)
                } else {
                    Duration::ZERO
                },
                counter,
                finished,
            )
        });
        servers.push((finish, receiver));
        let connection =
            SenderConnection::new("127.0.0.1", client.local_addr().unwrap().ip(), &mut OsRng);
        let channel = ControlChannel::from_stream(client, connection);
        let data = UdpSocket::bind("127.0.0.1:0").unwrap();
        data.set_nonblocking(true).unwrap();
        let control = UdpSocket::bind("127.0.0.1:0").unwrap();
        control.set_nonblocking(true).unwrap();
        let mut config = AudioSendConfig::generate(
            channel.connection(),
            StreamType::Realtime,
            StreamFormat::PCM_44100_16_STEREO,
            control.local_addr().unwrap().port(),
            TimingMode::Ntp,
            &mut OsRng,
        )
        .with_first_timestamp(PlaybackClock::first_timestamp());
        config.stream.shared_key = [index as u8 + 1; 32];
        let volume = Arc::new(AtomicU32::new(35));
        volumes.push(volume.clone());
        let (source, receiver) = mpsc::sync_channel(64);
        sources.push(source);
        let shared = SharedAudio {
            receiver,
            ready: ready_tx.clone(),
            clock: shared_clock.clone(),
            primed: primed.clone(),
        };
        let cancel = stop.clone();
        sessions.push(thread::spawn(move || {
            crate::drive_session(
                channel,
                config,
                data,
                control,
                Ipv4Addr::LOCALHOST,
                None,
                cancel,
                volume,
                Arc::new(AtomicU32::new(0)),
                None,
                Some(shared),
                None,
            )
            .map_err(|e| e.to_string())
        }));
    }
    drop(ready_tx);
    for _ in 0..2 {
        ready_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    }
    let started = Instant::now();
    let mut routers: Vec<_> = (0..2)
        .map(|index| {
            let control = crate::routing::RouteControl::new();
            control.channel.store(index + 1, Ordering::Relaxed);
            crate::routing::Router::new(control)
        })
        .collect();
    for index in 0..packets {
        let deadline =
            started + Duration::from_secs_f64(index as f64 * PACKET_FRAMES as f64 / 44100.0);
        if !startup_burst {
            thread::sleep(deadline.saturating_duration_since(Instant::now()));
        }
        if index == 50 {
            for volume in &volumes {
                volume.store(55, Ordering::Release);
            }
        }
        let value = index as i32 + 1;
        let samples: Vec<_> = (0..PACKET_FRAMES).flat_map(|_| [value, -value]).collect();
        for (source, router) in sources.iter().zip(&mut routers) {
            source
                .try_send(router.process(&samples, false))
                .expect("production scheduler must drain bounded queue despite slow feedback");
        }
        if index == 12 {
            primed.store(true, Ordering::Release);
        }
    }
    let drain_deadline = Instant::now()
        + if startup_burst {
            Duration::from_millis(150)
        } else {
            Duration::from_secs(2)
        };
    while counters
        .iter()
        .any(|counter| counter.load(Ordering::Acquire) < packets)
    {
        if Instant::now() >= drain_deadline {
            stop.store(true, Ordering::Release);
            panic!(
                "both sessions must drain all source packets: {:?}",
                counters
                    .iter()
                    .map(|counter| counter.load(Ordering::Acquire))
                    .collect::<Vec<_>>()
            );
        }
        thread::sleep(Duration::from_millis(2));
    }
    let stopping = Instant::now();
    stop.store(true, Ordering::Release);
    for session in sessions {
        session.join().unwrap().unwrap();
    }
    assert!(stopping.elapsed() < Duration::from_millis(2500));
    let mut observations = Vec::new();
    for (finish, server) in servers {
        let _ = finish.send(());
        let observed = server.join().unwrap();
        assert_eq!(observed.sequences.len(), packets);
        assert_eq!(observed.pcm_packets, packets);
        assert_eq!(observed.timestamps[0], 88200);
        assert!(
            observed
                .first_audio_sync_age
                .is_some_and(|age| age.abs() < 0.5),
            "the playback epoch must start after slow RECORD/FLUSH and source priming, not before setup: {:?}",
            observed.first_audio_sync_age
        );
        assert!(observed.syncs >= if startup_burst { 1 } else { 4 });
        if !startup_burst {
            assert!(
                observed.volume_while_feedback_pending,
                "live volume must not wait for slow feedback"
            );
            assert!(observed.stalled_windows.len() >= 2);
            for (audio, syncs) in &observed.stalled_windows {
                assert!(
                    *audio >= 100,
                    "audio stopped while feedback pending: {observed:?}"
                );
                assert!(*syncs >= 1, "sync service stopped while feedback pending");
            }
        }
        for pair in observed.sequences.windows(2) {
            assert_eq!(pair[1], pair[0].wrapping_add(1));
        }
        for pair in observed.timestamps.windows(2) {
            assert_eq!(pair[1], pair[0].wrapping_add(PACKET_FRAMES));
        }
        observations.push(observed);
    }
    assert_eq!(
        observations[0].timestamps, observations[1].timestamps,
        "both routes must preserve the same RTP timeline"
    );
}
