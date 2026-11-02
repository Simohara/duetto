//! Rust AirPlay protocol and Windows audio investigation executable.
//! GPL-3.0-or-later: uses cidermill-airplay. No Python runtime is used.
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod calibration;
mod capture;
mod control_pump;
mod diagnostics;
mod event_pump;
mod gui;
mod multistream;
mod playback_clock;
mod pyatv_session;
mod retransmit;
mod routing;
mod settings;
#[cfg(test)]
mod transport_tests;
mod vault;
use cidermill_airplay::audio::{
    Action, AudioSendConfig, AudioSendState, StreamFormat, StreamType, TimingMode,
};
use cidermill_airplay::pairing::{HapCredentials, TransientStyle};
use cidermill_airplay::{Auth, ControlChannel, OsRng};
use cpal::traits::{DeviceTrait, HostTrait};
use mdns_sd::{ServiceDaemon, ServiceEvent};
use std::{
    env,
    error::Error,
    net::UdpSocket,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

fn main() {
    diagnostics::install_panic_hook();
    if let Err(error) = run() {
        diagnostics::record_error(&error.to_string());
        eprintln!("失败: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("--audio-inputs") => audio_inputs(),
        Some("--scan") => scan(),
        Some("--pair") if args.len() == 3 => pair(&args[2]),
        Some("--test-speaker") if args.len() == 3 => send_audio(
            &args[2],
            None,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicU32::new(15)),
            None,
            None,
        ),
        Some("--bridge") if args.len() == 4 => send_audio(
            &args[2],
            Some(&args[3]),
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicU32::new(35)),
            None,
            None,
        ),
        Some("--bridge-many") if args.len() >= 5 => {
            let routes = args[3..]
                .iter()
                .enumerate()
                .map(|(i, host)| {
                    let c = routing::RouteControl::new();
                    c.channel.store(
                        if i == 0 {
                            1
                        } else if i == 1 {
                            2
                        } else {
                            0
                        },
                        Ordering::Relaxed,
                    );
                    (host.clone(), c)
                })
                .collect();
            multistream::run(
                args[2].clone(),
                routes,
                Arc::new(AtomicBool::new(false)),
                Arc::new(AtomicU32::new(0)),
                |s| println!("{s}"),
            )
            .map_err(|e| Box::new(e) as Box<dyn Error>)
        }
        Some("--selftest-fanout" | "--selftest-sweep") if args.len() == 5 => {
            for target in &args[3..] {
                let (host, _) = host_port(target)?;
                if !host.parse::<std::net::Ipv4Addr>()?.is_loopback() {
                    return Err("自检仅允许本机接收端".into());
                }
            }
            let routes = args[3..]
                .iter()
                .enumerate()
                .map(|(i, host)| {
                    let c = routing::RouteControl::new();
                    c.channel
                        .store(if i == 0 { 1 } else { 2 }, Ordering::Relaxed);
                    (host.clone(), c)
                })
                .collect();
            let stop = Arc::new(AtomicBool::new(false));
            let timer = stop.clone();
            let mode = Arc::new(AtomicU32::new(if args[1] == "--selftest-sweep" {
                0
            } else {
                1
            }));
            let mode_timer = mode.clone();
            let sweep = args[1] == "--selftest-sweep";
            thread::spawn(move || {
                if sweep {
                    thread::sleep(Duration::from_secs(2));
                    mode_timer.store(1, Ordering::Release);
                    thread::sleep(Duration::from_secs(3));
                    mode_timer.store(2, Ordering::Release);
                    thread::sleep(Duration::from_secs(3));
                    mode_timer.store(1, Ordering::Release);
                    thread::sleep(Duration::from_secs(2));
                    mode_timer.store(0, Ordering::Release);
                    thread::sleep(Duration::from_secs(2));
                } else {
                    thread::sleep(Duration::from_secs(10));
                }
                timer.store(true, Ordering::Release);
            });
            multistream::run(args[2].clone(), routes, stop, mode, |s| println!("{s}"))
                .map_err(|e| Box::new(e) as Box<dyn Error>)
        }
        None => gui::run(),
        _ => {
            println!(
                "AirBridge Rust 实验性验证程序（尚不是完整应用）\n\n--audio-inputs          列出 WASAPI 音频输入\n--scan                  扫描 AirPlay 服务\n--pair IP:PORT           配对音响并加密保存凭据\n--test-speaker IP:PORT  实际连接音响并播放低振幅测试音\n--bridge IP:PORT NAME    实际采集指定 CABLE Output 并发送到一台音响\n\n尚未实现原程序的完整功能。--test-speaker 会实际占用音响并发声。"
            );
            Ok(())
        }
    }
}

fn audio_inputs() -> Result<(), Box<dyn Error>> {
    let host = cpal::default_host();
    for device in host.input_devices()? {
        let name = device.name()?;
        match device.default_input_config() {
            Ok(config) => println!(
                "{name} | {} Hz | {} 通道 | {:?}",
                config.sample_rate().0,
                config.channels(),
                config.sample_format()
            ),
            Err(_) => println!("{name} | 默认录音格式不可用"),
        }
    }
    Ok(())
}

fn scan() -> Result<(), Box<dyn Error>> {
    let daemon = ServiceDaemon::new()?;
    let receiver = daemon.browse("_airplay._tcp.local.")?;
    let until = Instant::now() + Duration::from_secs(5);
    while Instant::now() < until {
        if let Ok(ServiceEvent::ServiceResolved(info)) =
            receiver.recv_timeout(Duration::from_millis(200))
        {
            println!(
                "{} | {:?} | port {}",
                info.get_fullname(),
                info.get_addresses(),
                info.get_port()
            );
        }
    }
    daemon.shutdown()?;
    Ok(())
}

fn pair(target: &str) -> Result<(), Box<dyn Error>> {
    use std::io::{self, Write};
    let (host, port) = host_port(target)?;
    if vault::exists(target) {
        return Err("此地址已有配对凭据，不会覆盖；如需重新配对，请在图形界面中操作".into());
    }
    let mut channel = ControlChannel::builder(host).port(port).connect()?;
    channel.hap_pin_start()?;
    eprint!("请输入音响显示的 PIN：");
    io::stderr().flush()?;
    let mut pin = String::new();
    io::stdin().read_line(&mut pin)?;
    if pin.trim().len() != 4 || !pin.trim().bytes().all(|v| v.is_ascii_digit()) {
        return Err("PIN 必须为四位数字".into());
    }
    let credential = channel.hap_pair_setup_shown_pin(pin.trim(), &mut OsRng)?;
    vault::save(target, &credential.to_storage_string(), false)?;
    println!("配对成功，凭据已用当前 Windows 用户加密保存。");
    Ok(())
}

fn host_port(target: &str) -> Result<(&str, u16), Box<dyn Error>> {
    let (host, port) = match target.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => (h, p.parse::<u16>()?),
        _ => (target, 7000),
    };
    let _ip: std::net::Ipv4Addr = host.parse()?;
    Ok((host, port))
}

#[derive(Debug)]
struct StageError {
    stage: String,
    source: cidermill_airplay::AirPlayError,
}
impl StageError {
    fn new(stage: impl Into<String>, source: cidermill_airplay::AirPlayError) -> Self {
        Self {
            stage: stage.into(),
            source,
        }
    }
}
impl std::fmt::Display for StageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}：{}", self.stage, self.source)
    }
}
impl std::error::Error for StageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// Match pyatv 0.18.0's `SET_PARAMETER` volume body (no trailing CRLF).
fn align_volume_request(request: &mut cidermill_airplay::rtsp::Request) {
    if request.method != "SET_PARAMETER" {
        return;
    }
    let Ok(text) = std::str::from_utf8(&request.body) else {
        return;
    };
    let Some(value) = text
        .strip_prefix("volume: ")
        .and_then(|v| v.trim().parse::<f64>().ok())
    else {
        return;
    };
    if value.is_finite() {
        request.body = format!("volume: {value:?}").into_bytes();
    }
}
#[cfg(test)]
mod protocol_tests {
    use super::*;
    #[test]
    fn volume_request_matches_pyatv_body_and_length() {
        use cidermill_airplay::rtsp::{Protocol, Request};
        let mut r = Request::new(
            "SET_PARAMETER",
            "rtsp://127.0.0.1/1",
            Protocol::Rtsp,
            b"volume: -18.000000\r\n".to_vec(),
        );
        align_volume_request(&mut r);
        assert_eq!(r.body, b"volume: -18.0");
        let wire = String::from_utf8(r.encode()).unwrap();
        assert!(wire.contains("Content-Length: 13\r\n"));
        assert!(wire.ends_with("\r\n\r\nvolume: -18.0"));
        let mut unrelated = Request::new(
            "SET_PARAMETER",
            "/",
            Protocol::Rtsp,
            b"progress: 1\r\n".to_vec(),
        );
        align_volume_request(&mut unrelated);
        assert_eq!(unrelated.body, b"progress: 1\r\n");
    }
}

fn send_audio(
    target: &str,
    input: Option<&str>,
    stop: Arc<AtomicBool>,
    volume: Arc<AtomicU32>,
    on_started: Option<Box<dyn Fn() + Send>>,
    shared: Option<SharedAudio>,
) -> Result<(), Box<dyn Error>> {
    send_audio_with_gain(target, input, stop, volume, on_started, shared, None)
}

const MANUAL_TEST_TONE_PEAK: f64 = 0.20;

fn manual_test_tone(frame: u64) -> [i32; 2] {
    let value = if frame < 4 * 44100 {
        (MANUAL_TEST_TONE_PEAK
            * 32767.0
            * (2.0 * std::f64::consts::PI * 440.0 * frame as f64 / 44100.0).sin())
        .round() as i32
    } else {
        0
    };
    if frame < 2 * 44100 {
        [value, 0]
    } else if frame < 4 * 44100 {
        [0, value]
    } else {
        [0, 0]
    }
}

/// One source and one shared NTP epoch for every speaker in a group.
struct SharedAudio {
    receiver: std::sync::mpsc::Receiver<Vec<i32>>,
    ready: std::sync::mpsc::Sender<()>,
    clock: Arc<playback_clock::SharedStart>,
    primed: Arc<AtomicBool>,
}

/// Optional live PCM gain is separate from the receiver's hardware volume.
fn send_audio_with_gain(
    target: &str,
    input: Option<&str>,
    stop: Arc<AtomicBool>,
    volume: Arc<AtomicU32>,
    on_started: Option<Box<dyn Fn() + Send>>,
    shared: Option<SharedAudio>,
    pcm_gain: Option<Arc<AtomicU32>>,
) -> Result<(), Box<dyn Error>> {
    let (host, port) = host_port(target)?;
    let mut channel = ControlChannel::builder(host).port(port).connect()?;
    let stored = vault::load(target)?
        .map(|v| HapCredentials::parse(&v))
        .transpose()?;
    if stored.is_none() {
        pyatv_session::transient_pin_start(&mut channel)?;
    }
    let auth = match &stored {
        Some(credentials) => Auth::Stored(credentials),
        None => Auth::Transient(TransientStyle::Pyatv),
    };
    channel
        .authenticate(auth, &mut OsRng)
        .map_err(|e| StageError::new("音响认证", e))?;
    let mut session =
        pyatv_session::start(&mut channel).map_err(|e| StageError::new("建立会话", e))?;
    let sent = Arc::new(AtomicU32::new(
        volume.load(Ordering::Acquire).min(100) * 0x101,
    ));
    let events = session
        .events
        .take()
        .map(|events| event_pump::EventPump::start(events, target.to_owned(), sent.clone()));
    let local = channel.connection().local_ip();
    let data = UdpSocket::bind((local, 0))?;
    // Audio and control datagrams must never park the playback loop in send().
    data.set_nonblocking(true)?;
    let control = UdpSocket::bind((local, 0))?;
    control.set_nonblocking(true)?;
    let mut config = AudioSendConfig::generate(
        channel.connection(),
        StreamType::Realtime,
        StreamFormat::PCM_44100_16_STEREO,
        control.local_addr()?.port(),
        TimingMode::Ntp,
        &mut OsRng,
    )
    .with_first_timestamp(playback_clock::PlaybackClock::first_timestamp());
    config.stream.shared_key = pyatv_session::audio_key(&channel)?;
    let result = drive_session(
        channel,
        config,
        data,
        control,
        host.parse()?,
        input,
        stop,
        volume,
        sent,
        on_started,
        shared,
        pcm_gain,
    );
    if result.is_err()
        && let Some(failure) = events.as_ref().and_then(|events| events.failure())
    {
        diagnostics::record_error(&failure);
    }
    result
}

/// The receiver volume in dB for the app's 0..=100 level; 0 mutes.
fn receiver_db(volume: u32) -> f64 {
    match volume.min(100) {
        0 => -144.0,
        v => -30.0 + v as f64 * 0.3,
    }
}

// These requests follow pyatv's asynchronous RTSP operations. Feedback is a
// separate best-effort task; it must not own the media scheduler's progress.
const RTSP_TIMEOUT: Duration = Duration::from_secs(10);
const FEEDBACK_INTERVAL: Duration = Duration::from_secs(2);

#[allow(clippy::too_many_arguments)]
fn drive_session(
    channel: ControlChannel,
    mut config: AudioSendConfig,
    data: UdpSocket,
    control: UdpSocket,
    peer_ip: std::net::Ipv4Addr,
    input: Option<&str>,
    stop: Arc<AtomicBool>,
    volume: Arc<AtomicU32>,
    sent: Arc<AtomicU32>,
    on_started: Option<Box<dyn Fn() + Send>>,
    shared: Option<SharedAudio>,
    pcm_gain: Option<Arc<AtomicU32>>,
) -> Result<(), Box<dyn Error>> {
    use cidermill_airplay::{
        audio::Step,
        rtsp::{Protocol, Request, Response},
    };
    use playback_clock::{PACKET_FRAMES, PlaybackClock, StartEpoch};
    // Feedback is scheduled on completion + 2 seconds, just like the Python
    // task, rather than by the state machine's send-time timer.
    config.feedback_interval = Duration::MAX;
    let mut packetizer = config.packetizer()?;
    // The session's receiver buffer, fixed when its first timestamp was chosen.
    let latency = config.first_timestamp.get();
    let mut state = AudioSendState::new(config);
    let mut pump = control_pump::ControlPump::new(channel)?;
    let mut pending = std::collections::HashMap::new();
    let mut feedback_pending = false;
    let mut feedback_due: Option<Instant> = None;
    let mut clock = None;
    let mut next_sync = Instant::now();
    let mut control_target = None;
    let mut backlog = retransmit::Backlog::new();
    let origin = Instant::now();
    let mut streaming: Option<Instant> = None;
    let mut next_audio = Instant::now();
    let mut extra_packets: Option<u64> = None;
    let mut first_sync = true;
    let mut capture = None;
    let mut tone_frame = 0;
    let mut last_volume = u32::MAX;
    let mut volume_pending = false;
    let mut stopping: Option<Instant> = None;
    let mut last_source_packet = Instant::now();
    loop {
        if stop.load(Ordering::Acquire) && stopping.is_none() {
            state.stop();
            capture = None;
            streaming = None;
            stopping = Some(Instant::now());
        }
        // Python sender bounds graceful teardown separately from playback.
        if stopping.is_some_and(|started| started.elapsed() >= Duration::from_secs(2)) {
            return Ok(());
        }
        let completions = match pump.poll() {
            Ok(completions) => completions,
            Err(_) if stopping.is_some() => return Ok(()),
            Err(error) => {
                return Err(format!(
                    "控制连接中断（{}，会话 {:.1} 秒）：{error}",
                    pump.status(),
                    origin.elapsed().as_secs_f64()
                )
                .into());
            }
        };
        for completion in completions {
            let Some(step) = pending.remove(&completion.cseq) else {
                continue;
            };
            if step == Step::Feedback {
                feedback_pending = false;
                feedback_due = Some(Instant::now() + FEEDBACK_INTERVAL);
                if let Err(error) = completion.result {
                    diagnostics::record_error(&format!("反馈请求超时，音频继续发送：{error}"));
                }
            } else {
                let response = completion
                    .result
                    .map_err(|e| format!("控制请求 {step:?} 超时：{e}"))?;
                if step == Step::SetParameter {
                    volume_pending = false;
                    if !response.is_success() {
                        return Err(Box::new(cidermill_airplay::AirPlayError::Status {
                            path: "SET_PARAMETER".into(),
                            code: response.status,
                            reason: None,
                        }));
                    }
                }
                state.on_response(&response)?;
            }
        }
        if stopping.is_none() {
            let new_volume = volume.load(Ordering::Acquire).min(100);
            if new_volume != last_volume && !volume_pending {
                state.set_volume(receiver_db(new_volume));
                event_pump::note_sent(&sent, new_volume);
                last_volume = new_volume;
                volume_pending = true;
            }
            if !feedback_pending && feedback_due.is_some_and(|due| Instant::now() >= due) {
                let mut request = Request::new("POST", "/feedback", Protocol::Rtsp, Vec::new());
                request.headers.set("User-Agent", "AirPlay/550.10");
                let cseq = pump.submit(request, RTSP_TIMEOUT)?;
                pending.insert(cseq, Step::Feedback);
                feedback_pending = true;
                feedback_due = None;
            }
        }
        retransmit::poll(&control, peer_ip, &backlog)?;
        match state.poll(origin.elapsed()) {
            Action::Send { step, mut request } => {
                align_volume_request(&mut request);
                request.headers.set("User-Agent", "AirPlay/550.10");
                if matches!(step, Step::Flush | Step::TeardownSession) {
                    request.headers.set("Session", "0");
                }
                let cseq = pump.submit(request, RTSP_TIMEOUT)?;
                pending.insert(cseq, step);
                if step == Step::Feedback {
                    feedback_pending = true;
                    // Python create_task(start_feedback) does not await a reply
                    // before RECORD/FLUSH or audio transmission.
                    state.on_response(&Response::new(Protocol::Rtsp, 200, "OK", Vec::new()))?;
                }
            }
            Action::ConnectData {
                data_port,
                control_port,
                ..
            } => {
                data.connect((peer_ip, data_port))?;
                control_target = Some(std::net::SocketAddr::from((peer_ip, control_port)));
                state.data_connected();
            }
            Action::StartStreaming { .. } => {
                if let Some(name) = input {
                    capture = Some(capture::Capture::start(name)?);
                }
                if let Some(source) = &shared {
                    source.ready.send(())?;
                }
                if let Some(callback) = &on_started {
                    callback();
                }
                let now = Instant::now();
                streaming = Some(now);
                next_audio = now;
                last_source_packet = now;
            }
            Action::Finished => return Ok(()),
            Action::Failed { reason, status, .. } => {
                if let Some(code) = status {
                    return Err(Box::new(cidermill_airplay::AirPlayError::Status {
                        path: "audio-session".into(),
                        code,
                        reason: Some(reason),
                    }));
                }
                return Err(reason.into());
            }
            _ => {}
        }
        if streaming.is_some()
            && clock.is_none()
            && shared
                .as_ref()
                .is_none_or(|source| source.primed.load(Ordering::Acquire))
        {
            let epoch = shared
                .as_ref()
                .map_or_else(StartEpoch::now, |source| source.clock.start());
            clock = Some(PlaybackClock::new(epoch, latency));
            next_sync = epoch.instant;
            streaming = Some(epoch.instant);
            next_audio = epoch.instant;
            last_source_packet = Instant::now();
        }
        // Independent sync service, including while a feedback/volume reply
        // is outstanding. Its byte representation is golden-tested vs pyatv.
        if stopping.is_none()
            && Instant::now() >= next_sync
            && let (Some(clock), Some(target)) = (&clock, control_target)
        {
            let bytes = clock.sync_packet(first_sync, clock.frames_now());
            control.send_to(&bytes, target)?;
            first_sync = false;
            next_sync = Instant::now() + Duration::from_secs(1);
        }
        let Some(started) = streaming else {
            thread::sleep(Duration::from_millis(2));
            continue;
        };
        if input.is_none() && shared.is_none() && started.elapsed() >= Duration::from_secs(6) {
            stop.store(true, Ordering::Release);
            continue;
        }
        if Instant::now() < next_audio {
            thread::sleep(
                next_audio
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(2)),
            );
            continue;
        }
        let samples = if let Some(source) = &mut capture {
            source.poll_packet(PACKET_FRAMES as usize)?
        } else if let Some(source) = &shared {
            if !source.primed.load(Ordering::Acquire) {
                None
            } else {
                match source.receiver.try_recv() {
                    Ok(samples) => Some(samples),
                    Err(std::sync::mpsc::TryRecvError::Empty) => None,
                    Err(std::sync::mpsc::TryRecvError::Disconnected)
                        if stop.load(Ordering::Acquire) =>
                    {
                        continue;
                    }
                    Err(error) => return Err(error.into()),
                }
            }
        } else {
            let mut samples = Vec::with_capacity(PACKET_FRAMES as usize * 2);
            for _ in 0..PACKET_FRAMES {
                samples.extend(manual_test_tone(tone_frame));
                tone_frame += 1;
            }
            Some(samples)
        };
        let Some(mut samples) = samples else {
            if clock.is_some() && last_source_packet.elapsed() > Duration::from_secs(5) {
                return Err("音频采集连续 5 秒无数据".into());
            }
            thread::sleep(Duration::from_millis(2));
            continue;
        };
        last_source_packet = Instant::now();
        if samples.len() != PACKET_FRAMES as usize * 2 {
            return Err("音频帧数无效".into());
        }
        if let Some(gain) = &pcm_gain {
            scale_pcm(&mut samples, f32::from_bits(gain.load(Ordering::Acquire)));
        }
        let packet = packetizer.packet(&samples)?;
        sent_or_dropped(data.send(&packet), &DROPPED_PACKETS)?;
        backlog.remember(packet);
        // Shared PCM is already paced by capture; a second clock accumulates
        // callback bursts and oscillator drift in one speaker's bounded queue.
        if shared.is_some() {
            continue;
        }
        let frames_sent = packetizer.packets_sent() * u64::from(PACKET_FRAMES);
        match extra_packets {
            None => {
                extra_packets = Some(playback_clock::catch_up_packets(
                    frames_sent,
                    started.elapsed(),
                ))
            }
            Some(remaining) => extra_packets = Some(remaining.saturating_sub(1)),
        }
        if extra_packets == Some(0) {
            extra_packets = None;
            next_audio =
                Instant::now() + playback_clock::sleep_after(frames_sent, started.elapsed());
        }
    }
}

/// Audio datagrams of every route that a full socket buffer refused since the
/// GUI last started a session.
static DROPPED_PACKETS: AtomicU64 = AtomicU64::new(0);

fn sent_or_dropped(
    result: std::io::Result<usize>,
    dropped: &AtomicU64,
) -> Result<(), Box<dyn Error>> {
    match result {
        Ok(_) => Ok(()),
        // A full socket buffer (Wi-Fi congestion) loses this datagram as the
        // network could; it stays in the backlog for a retransmit request.
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
            dropped.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
        Err(error) => Err(format!("音频 UDP 发送失败：{error}").into()),
    }
}

fn scale_pcm(samples: &mut [i32], gain: f32) {
    let gain = if gain.is_finite() {
        gain.clamp(0.0, 1.0)
    } else {
        0.0
    };
    for sample in samples {
        *sample = (*sample as f32 * gain).round() as i32;
    }
}

#[cfg(test)]
mod pcm_gain_tests {
    #[test]
    fn manual_test_tone_has_audible_headroom_and_keeps_channels_separate() {
        let left = super::manual_test_tone(25);
        let right = super::manual_test_tone(2 * 44100 + 25);
        assert!(left[0] > 6000 && left[1] == 0);
        assert_eq!(right, [0, left[0]]);
        assert_eq!(super::manual_test_tone(4 * 44100), [0, 0]);

        let mut samples = [left[0], 0];
        super::scale_pcm(&mut samples, 0.5);
        assert_eq!(samples[0], (left[0] as f32 * 0.5).round() as i32);
        super::scale_pcm(&mut samples, 0.0);
        assert_eq!(samples, [0, 0]);
    }

    #[test]
    fn only_refused_datagrams_are_counted_as_dropped() {
        use std::{io, sync::atomic::AtomicU64};
        let dropped = AtomicU64::new(0);
        assert!(super::sent_or_dropped(Ok(1), &dropped).is_ok());
        assert!(super::sent_or_dropped(Err(io::ErrorKind::WouldBlock.into()), &dropped).is_ok());
        assert!(
            super::sent_or_dropped(Err(io::ErrorKind::ConnectionReset.into()), &dropped).is_err()
        );
        assert_eq!(dropped.into_inner(), 1);
    }

    #[test]
    fn live_gain_scales_without_amplification_or_invalid_values() {
        let mut samples = [1000, -1000];
        super::scale_pcm(&mut samples, 0.25);
        assert_eq!(samples, [250, -250]);
        super::scale_pcm(&mut samples, 2.0);
        assert_eq!(samples, [250, -250]);
        super::scale_pcm(&mut samples, f32::NAN);
        assert_eq!(samples, [0, 0]);
    }
}
