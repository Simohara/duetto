//! Duetto desktop window: a WebView2 page (web/) drawn and animated with
//! GSAP, driven by this module. The page sends one JSON command per user
//! action; the application state is pushed back as a JSON snapshot.
use crate::routing::RouteControl;
use cidermill_airplay::{ControlChannel, OsRng};
use cpal::traits::{DeviceTrait, HostTrait};
use mdns_sd::{ServiceDaemon, ServiceEvent};
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, Ordering},
        mpsc::{self, Receiver, Sender},
    },
    thread,
    time::{Duration, Instant},
};

#[derive(Clone, Debug, Default, PartialEq)]
struct Speaker {
    name: String,
    address: String,
    /// TXT `deviceid`: identifies the speaker across IP address changes.
    id: Option<String>,
    /// TXT `tsid`: members of one Home stereo pair share it.
    pair: Option<String>,
    /// TXT asks for a connection password, which this version cannot send.
    password: bool,
}
/// pyatv's rule: `pw=true`, or bit 0x80 of the hex `sf`/`flags` value.
fn txt_requires_password(pw: Option<&str>, flags: Option<&str>) -> bool {
    pw.is_some_and(|v| v.eq_ignore_ascii_case("true"))
        || flags.is_some_and(|v| {
            let v = v.trim();
            let hex = v
                .strip_prefix("0x")
                .or_else(|| v.strip_prefix("0X"))
                .unwrap_or(v);
            u64::from_str_radix(hex, 16).is_ok_and(|bits| bits & 0x80 != 0)
        })
}
/// An authentication failure of a speaker whose TXT asks for a password gets
/// the likely cause; the attempt itself is not blocked, as TXT may be stale.
fn password_hint(message: &str, speakers: &[Speaker], involved: &[String]) -> bool {
    (message.contains("验证失败") || message.contains("音响认证"))
        && speakers.iter().any(|s| {
            // A typed IP and a scanned IP:7000 name the same receiver.
            let target = super::host_port(&s.address).ok();
            s.password
                && involved.iter().any(|a| {
                    target.is_some()
                        && super::host_port(a).ok() == target
                        // A multistream failure names its speaker; only that one counts.
                        && (!message.contains("验证失败") || message.contains(&format!("音响 {a} ")))
                })
        })
}
/// A speaker that already has a credential is re-paired only after the user
/// confirmed it for this same host.
fn needs_repair_confirm(pending: Option<&str>, host: &str, replace: bool, exists: bool) -> bool {
    exists && !(replace && pending == Some(host))
}
fn pair_failure_text(error: &(dyn std::error::Error + 'static), had: bool) -> String {
    let text = match error.downcast_ref::<mpsc::RecvTimeoutError>() {
        Some(mpsc::RecvTimeoutError::Timeout) => "90 秒内未提交 PIN，已取消配对。",
        // The PIN prompt was dropped by Stop.
        Some(mpsc::RecvTimeoutError::Disconnected) => "已取消配对。",
        None => "配对失败或超时，请检查 PIN 和音响访问设置。",
    };
    if had {
        format!("{text}旧凭据未更改。")
    } else {
        text.into()
    }
}
enum Event {
    /// One mDNS resolution with all its IPv4 `ip:port` addresses, sorted.
    Found(Speaker, Vec<String>),
    ScanDone,
    PairPin(Sender<String>),
    Message(String),
    Connected(String),
    Reconnecting(String),
    WorkerDone(String),
    Measured(
        Arc<AtomicU32>,
        Vec<String>,
        Result<crate::calibration::Proposal, String>,
    ),
}
/// The test signal plays at one level on every route, through the same
/// receiver volumes and PCM trims as playback, so the microphone measures the
/// difference a listener hears and no receiver volume curve is assumed.
fn test_gain(test_volume: u32) -> f32 {
    test_volume.min(100) as f32 / 100.0
}
const SETTLE_AFTER_CONNECT: Duration = Duration::from_secs(30);
/// Consecutive failed reconnects before giving up (about four minutes).
const MAX_RECONNECTS: u32 = 10;
/// Measurement: 4 s for the queue to drain, then a 13 s recording.
const MEASURE_TIME: Duration = Duration::from_secs(17);
fn delay_us(ms: f64) -> u32 {
    (ms.clamp(0.0, 2000.0) * 1000.0).round() as u32
}
/// A Home stereo pair leader does not forward the other channel to its
/// partner, and the pair may share one receiver volume.
fn stereo_pair_notice(
    speakers: &[Speaker],
    routes: &HashMap<String, RouteUi>,
    selected: &[String],
) -> String {
    let mut notes = Vec::new();
    let mut pairs: Vec<&String> = Vec::new();
    for pair in speakers.iter().filter_map(|s| s.pair.as_ref()) {
        if pairs.contains(&pair) {
            continue;
        }
        pairs.push(pair);
        let chosen: Vec<&Speaker> = speakers
            .iter()
            .filter(|s| s.pair.as_ref() == Some(pair) && selected.contains(&s.address))
            .collect();
        let volume = |s: &Speaker| routes.get(&s.address).map(|r| r.volume);
        match chosen.as_slice() {
            [one] => notes.push(format!(
                "「{}」属于家庭 App 立体声对，只连一台时另一台不会发声：请两台都勾选，并分别设为左、右声道。",
                one.name
            )),
            [a, b] if volume(a) != volume(b) => notes.push(format!(
                "「{}」与「{}」是同一个立体声对，独立音量不同；立体声对可能联动音量，建议设为相同，用「电平修正」平衡。",
                a.name, b.name
            )),
            _ => {}
        }
    }
    notes.join(" ")
}
/// Index of the saved device, else of the previous choice, else 0.
fn reselect(devices: &[String], saved: &str, previous: Option<String>) -> usize {
    let at = |name: &str| devices.iter().position(|d| d == name);
    at(saved)
        .or_else(|| previous.and_then(|name| at(&name)))
        .unwrap_or(0)
}
fn manual_test_gain(master_volume: u32, test_volume: u32) -> f32 {
    master_volume.min(100) as f32 / 100.0 * (test_volume.min(100) as f32 / 100.0)
}
/// Estimated playback level relative to full scale, as the speaker row shows it.
fn level_text(volume: u32, trim: f64, master: u32) -> String {
    if master == 0 || volume == 0 {
        return "静音".into();
    }
    let db = -30.0 + volume as f64 * 0.3 + trim + 20.0 * (master as f64 / 100.0).log10();
    let sign = if db > 0.0 {
        "+"
    } else if db < 0.0 {
        "−"
    } else {
        ""
    };
    format!("{sign}{:.1} dB", db.abs())
}

struct RouteUi {
    selected: bool,
    mode: u32,
    /// Milliseconds, 0.1 ms resolution.
    delay: f64,
    volume: u32,
    /// Calibrated PCM level correction in dB (<= 0).
    trim: f64,
    /// The other half of this speaker's stereo pair, by route address.
    partner: Option<String>,
    control: RouteControl,
}
const ROUTE_VOLUME: u32 = 35;
impl RouteUi {
    fn new() -> Self {
        let master = ROUTE_VOLUME;
        let control = RouteControl::new();
        control.volume.store(master, Ordering::Relaxed);
        Self {
            selected: false,
            mode: 0,
            delay: 0.0,
            volume: master,
            trim: 0.0,
            partner: None,
            control,
        }
    }
    fn set_mode(&mut self, mode: u32) {
        self.mode = mode;
        self.control.channel.store(mode, Ordering::Release);
    }
    /// Nothing calibrated or chosen on this row yet.
    fn is_default(&self) -> bool {
        self.mode == 0
            && self.delay == 0.0
            && self.trim == 0.0
            && self.partner.is_none()
            && self.volume == ROUTE_VOLUME
    }
}
fn sync_gains(
    routes: &HashMap<String, RouteUi>,
    session_routes: &[String],
    master_volume: u32,
    test_volume: u32,
    test_active: bool,
    tone_gain: &AtomicU32,
) {
    // The standalone test tone is still output audio, so it observes the
    // master level as well as its dedicated test-volume setting.
    tone_gain.store(
        manual_test_gain(master_volume, test_volume).to_bits(),
        Ordering::Release,
    );
    let master = (master_volume.min(100) as f32 / 100.0).to_bits();
    for route in routes.values() {
        route.control.master_gain.store(master, Ordering::Release);
    }
    if test_active {
        for id in session_routes {
            if let Some(route) = routes.get(id) {
                route
                    .control
                    .test_gain
                    .store(test_gain(test_volume).to_bits(), Ordering::Release);
            }
        }
    }
}

/// One user action from the page. Values are checked again here: the page is
/// ours, but the IPC boundary is still where invalid input stops.
#[derive(Deserialize)]
#[serde(tag = "cmd", rename_all = "camelCase")]
enum Command {
    Ready,
    Scan,
    RefreshInputs,
    RefreshMics,
    OpenMixer,
    OpenDriverPage,
    ExportDiagnostics,
    AddHost,
    Start,
    Stop,
    Tone,
    /// `replace` confirms re-pairing a speaker that has a credential.
    PairDevice {
        #[serde(default)]
        replace: bool,
    },
    CancelPair,
    ImportLegacyCredentials,
    ToggleTest,
    Measure,
    SetDevice {
        index: usize,
    },
    SetMic {
        index: usize,
    },
    SetMaster {
        value: u32,
    },
    SetTestVolume {
        value: u32,
    },
    SetBuffer {
        value: u32,
    },
    SetReconnect {
        on: bool,
    },
    SetTheme {
        theme: String,
    },
    Route {
        address: String,
        selected: Option<bool>,
        mode: Option<u32>,
        delay: Option<f64>,
        trim: Option<f64>,
        volume: Option<u32>,
    },
    MakePair {
        left: String,
        right: String,
    },
    Unpair {
        address: String,
    },
    SwapPair {
        address: String,
    },
    SetTarget {
        address: String,
    },
    SetHost {
        host: String,
    },
    SubmitPin {
        pin: String,
    },
}

struct App {
    events: Sender<Event>,
    receiver: Receiver<Event>,
    devices: Vec<String>,
    selected: usize,
    /// The saved CABLE input and microphone: kept while that device is
    /// absent, so a missing USB microphone is not replaced on the next save.
    input_name: String,
    mic_name: String,
    speakers: Vec<Speaker>,
    routes: HashMap<String, RouteUi>,
    host: String,
    pin_sender: Option<Sender<String>>,
    /// The host waiting for the user to confirm re-pairing.
    repair_confirm: Option<String>,
    scanning: bool,
    busy: bool,
    /// The run state shown while busy and not connected: "connecting", "tone" or "pairing".
    activity: &'static str,
    connected: bool,
    measuring: bool,
    reconnect: bool,
    cpu_label: String,
    webview_label: String,
    status: String,
    microphones: Vec<String>,
    mic_selected: usize,
    test_volume: u32,
    tone_gain: Arc<AtomicU32>,
    test_mode: Arc<AtomicU32>,
    session_routes: Vec<String>,
    transition: Option<(Instant, bool)>,
    stop: Arc<AtomicBool>,
    volume_ui: u32,
    /// Appended to the connected message for the session being started.
    start_notice: String,
    /// deviceid -> first IPv4 address seen in the current scan.
    scan_seen: HashMap<String, String>,
    /// The last measurement result stays visible after its settling time.
    measured: bool,
    /// Receivers take ~20 s after connecting to settle on the shared
    /// timeline (measured 2026-11-02); calibrating earlier is meaningless.
    connected_at: Option<Instant>,
    /// Receiver playout buffer for the next session, 300-2000 ms.
    buffer_ms: u32,
    /// "light", "dark" or "system".
    theme: String,
    /// Last measurement: right minus left arrival (ms) and level (dB).
    last_result: Option<(f64, f64)>,
    measuring_since: Option<Instant>,
    /// Last settings written to disk, to save changes within a second.
    saved_json: String,
    dirty_since: Option<Instant>,
    /// The settings file could not be read or moved aside: never overwrite it.
    save_blocked: bool,
    /// Last snapshot sent to the page.
    pushed: String,
}
impl App {
    fn new() -> Self {
        let (events, receiver) = mpsc::channel();
        let mut app = Self {
            events,
            receiver,
            devices: Vec::new(),
            selected: 0,
            input_name: String::new(),
            mic_name: String::new(),
            speakers: Vec::new(),
            routes: HashMap::new(),
            host: String::new(),
            pin_sender: None,
            repair_confirm: None,
            scanning: false,
            busy: false,
            activity: "connecting",
            connected: false,
            measuring: false,
            reconnect: false,
            cpu_label: cpu_compatibility_label(),
            webview_label: wry::webview_version().unwrap_or_else(|_| "未知版本".into()),
            microphones: Vec::new(),
            mic_selected: 0,
            test_volume: 100,
            tone_gain: Arc::new(AtomicU32::new(1.0_f32.to_bits())),
            test_mode: Arc::new(AtomicU32::new(0)),
            session_routes: Vec::new(),
            transition: None,
            status: "选择音响及声道，桥接使用同一个 CABLE Output。".into(),
            stop: Arc::new(AtomicBool::new(false)),
            volume_ui: 100,
            start_notice: String::new(),
            scan_seen: HashMap::new(),
            measured: false,
            connected_at: None,
            buffer_ms: 2000,
            theme: "system".into(),
            last_result: None,
            measuring_since: None,
            saved_json: String::new(),
            dirty_since: None,
            save_blocked: false,
            pushed: String::new(),
        };
        app.refresh_inputs();
        app.refresh_mics();
        match crate::settings::load() {
            Ok(Some(settings)) => app.apply_settings(&settings),
            Ok(None) => {}
            Err((error, blocked)) => app.settings_load_failed(&error, blocked),
        }
        app.update_gains();
        app.saved_json = app.settings_json();
        app
    }
    fn settings_load_failed(&mut self, error: &str, blocked: bool) {
        crate::diagnostics::record_error(&format!("设置文件无法读取：{error}"));
        self.save_blocked = blocked;
        self.status = if blocked {
            "设置文件无法读取，本次不会保存设置。".into()
        } else {
            "设置文件无法读取，已备份为 settings.json.bad 并使用默认设置。".into()
        };
    }
    fn apply_settings(&mut self, settings: &crate::settings::Settings) {
        self.volume_ui = settings.playback_master();
        self.test_volume = settings.test_volume;
        self.reconnect = settings.reconnect;
        self.buffer_ms = settings.buffer_ms;
        self.theme = settings.theme.clone();
        self.input_name = settings.input.clone();
        self.mic_name = settings.microphone.clone();
        if let Some(i) = self
            .microphones
            .iter()
            .position(|name| name == &settings.microphone)
        {
            self.mic_selected = i;
        }
        if let Some(i) = self.devices.iter().position(|name| name == &settings.input) {
            self.selected = i;
        }
        for (address, saved) in &settings.routes {
            let volume = settings.playback_route_volume(saved);
            let control = RouteControl::new();
            control.channel.store(saved.mode, Ordering::Relaxed);
            control
                .delay_us
                .store(delay_us(saved.delay), Ordering::Relaxed);
            control.volume.store(volume, Ordering::Relaxed);
            control
                .trim_db
                .store((saved.trim as f32).to_bits(), Ordering::Relaxed);
            self.speakers.push(Speaker {
                name: saved.name.clone(),
                address: address.clone(),
                id: Some(saved.id.clone()).filter(|id| !id.is_empty()),
                pair: Some(saved.home_pair.clone()).filter(|p| !p.is_empty()),
                // Known again after the next scan; not saved.
                password: false,
            });
            self.routes.insert(
                address.clone(),
                RouteUi {
                    selected: saved.enabled,
                    mode: saved.mode,
                    delay: saved.delay,
                    volume,
                    trim: saved.trim,
                    partner: Some(saved.partner.clone()).filter(|p| !p.is_empty()),
                    control,
                },
            );
        }
        self.repair_pairs(!settings.pairs);
    }
    fn update_gains(&self) {
        sync_gains(
            &self.routes,
            &self.session_routes,
            self.volume_ui,
            self.test_volume,
            self.test_mode.load(Ordering::Acquire) != 0,
            &self.tone_gain,
        );
    }
    /// Selects the saved device when present, else keeps the current one.
    fn refresh_inputs(&mut self) {
        let chosen = self.devices.get(self.selected).cloned();
        self.devices = cpal::default_host()
            .input_devices()
            .map(|list| {
                list.filter_map(|d| d.name().ok())
                    .filter(|n| {
                        let x = n.to_ascii_uppercase();
                        x.starts_with("CABLE") && x.contains("OUTPUT")
                    })
                    .collect()
            })
            .unwrap_or_default();
        self.selected = reselect(&self.devices, &self.input_name, chosen);
    }
    fn refresh_mics(&mut self) {
        let chosen = self.microphones.get(self.mic_selected).cloned();
        self.microphones = cpal::default_host()
            .input_devices()
            .map(|v| {
                v.filter_map(|d| d.name().ok())
                    .filter(|n| {
                        !n.to_ascii_uppercase().starts_with("CABLE")
                            && !n.to_ascii_uppercase().contains("LOOPBACK")
                    })
                    .collect()
            })
            .unwrap_or_default();
        self.mic_selected = reselect(&self.microphones, &self.mic_name, chosen);
    }
    fn scan(&mut self) {
        if self.scanning {
            return;
        }
        self.scanning = true;
        self.scan_seen.clear();
        let tx = self.events.clone();
        thread::spawn(move || {
            let result = (|| -> Result<(), Box<dyn std::error::Error>> {
                let daemon = ServiceDaemon::new()?;
                let receiver = daemon.browse("_airplay._tcp.local.")?;
                let until = Instant::now() + Duration::from_secs(5);
                while Instant::now() < until {
                    if let Ok(ServiceEvent::ServiceResolved(info)) =
                        receiver.recv_timeout(Duration::from_millis(200))
                    {
                        let mut ips: Vec<_> = info
                            .get_addresses()
                            .iter()
                            .filter(|ip| ip.is_ipv4())
                            .collect();
                        if ips.is_empty() {
                            continue;
                        }
                        // The set's order is arbitrary; sorting keeps the fallback stable.
                        ips.sort();
                        let addresses = ips
                            .iter()
                            .map(|ip| format!("{}:{}", ip, info.get_port()))
                            .collect();
                        let _ = tx.send(Event::Found(
                            Speaker {
                                name: info
                                    .get_fullname()
                                    .trim_end_matches("._airplay._tcp.local.")
                                    .to_owned(),
                                address: String::new(),
                                id: info
                                    .get_property_val_str("deviceid")
                                    .filter(|id| !id.is_empty())
                                    .map(str::to_ascii_uppercase),
                                pair: info
                                    .get_property_val_str("tsid")
                                    .filter(|tsid| !tsid.is_empty())
                                    .map(str::to_ascii_uppercase),
                                password: txt_requires_password(
                                    info.get_property_val_str("pw"),
                                    info.get_property_val_str("sf")
                                        .or_else(|| info.get_property_val_str("flags")),
                                ),
                            },
                            addresses,
                        ));
                    }
                }
                daemon.shutdown()?;
                Ok(())
            })();
            if result.is_err() {
                let _ = tx.send(Event::Message("扫描失败，请检查网络。".into()));
            }
            let _ = tx.send(Event::ScanDone);
        });
    }
    fn start(&mut self, tone: bool) {
        if self.busy {
            return;
        }
        let mut host = self.host.trim().to_owned();
        if tone && super::host_port(&host).is_err() {
            self.status = "测试音请先选择一台音响。".into();
            return;
        }
        let input = if tone {
            None
        } else {
            self.devices.get(self.selected).cloned()
        };
        if !tone && input.is_none() {
            self.status = "未找到 CABLE Output，请先安装驱动并刷新。".into();
            return;
        }
        let mut routes: Vec<_> = self
            .speakers
            .iter()
            .filter_map(|s| {
                self.routes
                    .get(&s.address)
                    .filter(|r| r.selected)
                    .map(|r| (s.address.clone(), r.control.clone()))
            })
            .collect();
        if tone || routes.is_empty() {
            if super::host_port(&host).is_err() {
                self.status = "请勾选音响或输入 IPv4 地址。".into();
                return;
            }
            // A typed IP and a scanned IP:7000 identify the same receiver.
            // Keep its existing key so calibration and saved pairing still apply.
            if let Some(address) = self
                .routes
                .keys()
                .find(|address| super::host_port(address).ok() == super::host_port(&host).ok())
            {
                host = address.clone();
            }
            let route = self.routes.entry(host.clone()).or_insert_with(RouteUi::new);
            if !tone {
                route.selected = true;
            }
            let control = route.control.clone();
            if !self.speakers.iter().any(|s| s.address == host) {
                self.speakers.push(Speaker {
                    name: "手动添加".into(),
                    address: host.clone(),
                    ..Default::default()
                });
            }
            routes = vec![(host.clone(), control)];
        }
        self.start_notice = if tone {
            String::new()
        } else {
            let selected: Vec<String> = routes.iter().map(|(address, _)| address.clone()).collect();
            stereo_pair_notice(&self.speakers, &self.routes, &selected)
        };
        crate::playback_clock::set_buffer_ms(self.buffer_ms);
        self.update_gains();
        for (_, control) in &routes {
            control
                .master_gain
                .store((self.volume_ui as f32 / 100.0).to_bits(), Ordering::Release);
        }
        self.stop = Arc::new(AtomicBool::new(false));
        self.test_mode = Arc::new(AtomicU32::new(0));
        self.session_routes = if tone {
            Vec::new()
        } else {
            routes.iter().map(|r| r.0.clone()).collect()
        };
        self.busy = true;
        self.activity = if tone { "tone" } else { "connecting" };
        // A new session must be measured again before it counts as aligned.
        self.last_result = None;
        super::DROPPED_PACKETS.store(0, Ordering::Relaxed);
        self.connected = false;
        self.measuring = false;
        self.transition = None;
        self.status = "正在连接音响…".into();
        let tx = self.events.clone();
        let stop = self.stop.clone();
        // Bridge playback uses the selected routes and does not require the
        // separate pairing/test target field to name one of those routes.
        let tone_volume = if tone {
            routes.first().map(|(_, control)| control.volume.clone())
        } else {
            None
        };
        let tone_gain = self.tone_gain.clone();
        let test_mode = self.test_mode.clone();
        let reconnect = self.reconnect;
        thread::spawn(move || {
            let result = if let Some(volume) = tone_volume {
                let started = tx.clone();
                super::send_audio_with_gain(
                    &host,
                    None,
                    stop.clone(),
                    volume,
                    Some(Box::new(move || {
                        let _ = started.send(Event::Message(
                            "协议发送已开始；实际发声需现场确认。".into(),
                        ));
                    })),
                    None,
                    Some(tone_gain),
                )
                .map_err(|e| e.to_string())
            } else {
                let input = input.unwrap();
                let mut attempt = 0u32;
                loop {
                    let local_stop = Arc::new(AtomicBool::new(false));
                    let watcher_local = local_stop.clone();
                    let watcher_user = stop.clone();
                    let watcher = thread::spawn(move || {
                        while !watcher_local.load(Ordering::Acquire) {
                            if watcher_user.load(Ordering::Acquire) {
                                watcher_local.store(true, Ordering::Release);
                                break;
                            }
                            thread::sleep(Duration::from_millis(100));
                        }
                    });
                    let progress = tx.clone();
                    let began = Instant::now();
                    let result = crate::multistream::run(
                        input.clone(),
                        routes.clone(),
                        local_stop.clone(),
                        test_mode.clone(),
                        move |s| {
                            let _ = progress.send(Event::Connected(s));
                        },
                    );
                    local_stop.store(true, Ordering::Release);
                    let _ = watcher.join();
                    if stop.load(Ordering::Acquire) {
                        break Ok(());
                    }
                    // A session that played for a minute was healthy: count
                    // only consecutive failures, so drops hours apart never
                    // exhaust the retries.
                    if began.elapsed() >= Duration::from_secs(60) {
                        attempt = 0;
                    }
                    if result.is_ok()
                        || !reconnect
                        || attempt >= MAX_RECONNECTS
                        || result.as_ref().is_err_and(|e| !e.retryable)
                    {
                        break result.map_err(|e| e.to_string());
                    }
                    test_mode.store(0, Ordering::Release);
                    attempt += 1;
                    let seconds = (1u64 << attempt.min(5)).min(30);
                    let _ = tx.send(Event::Reconnecting(format!(
                        "连接中断，{seconds} 秒后重试（第 {attempt}/{MAX_RECONNECTS} 次）；可停止。"
                    )));
                    for _ in 0..seconds * 10 {
                        if stop.load(Ordering::Acquire) {
                            break;
                        }
                        thread::sleep(Duration::from_millis(100));
                    }
                    if stop.load(Ordering::Acquire) {
                        break Ok(());
                    }
                }
            };
            let message = match result {
                Ok(()) => "已停止。".into(),
                Err(e) if stop.load(Ordering::Acquire) && e.contains("取消") => "已停止。".into(),
                Err(e) => format!("连接或播放失败：{}", e),
            };
            let _ = tx.send(Event::WorkerDone(message));
        });
    }
    fn toggle_test(&mut self) {
        if !self.connected || self.measuring || self.transition.is_some() {
            return;
        }
        let mode = self.test_mode.load(Ordering::Acquire);
        if mode == 0 {
            if self.session_routes.len() != 2 {
                self.status = "请选择恰好两台音响。".into();
                return;
            }
            let mut modes = self
                .session_routes
                .iter()
                .filter_map(|id| self.routes.get(id).map(|r| r.mode))
                .collect::<Vec<_>>();
            modes.sort();
            if modes != [1, 2] {
                self.status = "请将两台音响分别设置为左声道和右声道。".into();
                return;
            }
            let Some(reference) = self
                .session_routes
                .iter()
                .filter_map(|id| self.routes.get(id))
                .map(|r| r.control.volume.load(Ordering::Acquire))
                .min()
            else {
                return;
            };
            if reference == 0 {
                self.status = "两台音响的播放音量必须大于零。".into();
                return;
            }
            for id in &self.session_routes {
                if let Some(r) = self.routes.get(id) {
                    r.control
                        .test_gain
                        .store(test_gain(self.test_volume).to_bits(), Ordering::Release);
                }
            }
            self.measured = false;
            // Only PCM changes: speaker hardware volume remains unchanged during measurement.
            self.test_mode.store(1, Ordering::Release);
            self.transition = Some((Instant::now() + Duration::from_secs(5), true));
            self.status = "正在切换测试音，等待播放缓冲排空…".into();
        } else {
            // Apply user-selected playback levels only when leaving the test.
            for id in &self.session_routes {
                if let Some(r) = self.routes.get(id) {
                    r.control.volume.store(r.volume, Ordering::Release);
                }
            }
            self.transition = Some((Instant::now() + Duration::from_secs(5), false));
            self.status = "正在恢复播放音量，随后恢复应用声音…".into();
            self.save_settings();
        }
    }
    fn calibrate(&mut self) {
        if !self.connected
            || self.measuring
            || self.transition.is_some()
            || self.test_mode.load(Ordering::Acquire) != 1
        {
            return;
        }
        if self.test_volume == 0 {
            self.status = "测试音量为 0%，请先调高音量并等待播放稳定。".into();
            return;
        }
        if self.volume_ui == 0 {
            self.status = "总音量为 0%，请先调高音量并等待播放稳定。".into();
            return;
        }
        let settled = self.connected_at.map_or(Duration::ZERO, |at| at.elapsed());
        if settled < SETTLE_AFTER_CONNECT {
            self.status = format!(
                "刚连接，两台音响的同步还在稳定，请 {} 秒后再测量。",
                (SETTLE_AFTER_CONNECT - settled).as_secs() + 1
            );
            return;
        }
        let Some(mic) = self.microphones.get(self.mic_selected).cloned() else {
            self.status = "请选择物理麦克风。".into();
            return;
        };
        let left = self
            .session_routes
            .iter()
            .find(|id| self.routes.get(*id).is_some_and(|r| r.mode == 1))
            .cloned();
        let right = self
            .session_routes
            .iter()
            .find(|id| self.routes.get(*id).is_some_and(|r| r.mode == 2))
            .cloned();
        let (Some(left), Some(right)) = (left, right) else {
            self.status = "请指定左、右音响。".into();
            return;
        };
        let a = &self.routes[&left];
        let b = &self.routes[&right];
        let (dl, dr, tl, tr) = (a.delay, b.delay, a.trim, b.trim);
        if a.volume == 0 || b.volume == 0 {
            self.status = "自动音量调平需要两台音响的播放音量都大于零。".into();
            return;
        }
        self.measuring = true;
        self.measuring_since = Some(Instant::now());
        self.status = "正在测量延迟和音量，约需 20 秒，请保持安静。".into();
        let tx = self.events.clone();
        let stop = self.stop.clone();
        let mode = self.test_mode.clone();
        thread::spawn(move || {
            let result = crate::calibration::measure(mic, stop, mode.clone(), dl, dr, tl, tr);
            let _ = tx.send(Event::Measured(mode, vec![left, right], result));
        });
    }
    /// HAP pairing with the PIN a speaker shows (not a stereo pair).
    fn pair_device(&mut self, replace: bool) {
        if self.busy {
            return;
        }
        let host = self.host.trim().to_owned();
        if super::host_port(&host).is_err() {
            self.status = "请选择音响或输入 IPv4 地址。".into();
            return;
        }
        let had = super::vault::exists(&host);
        if needs_repair_confirm(self.repair_confirm.as_deref(), &host, replace, had) {
            self.repair_confirm = Some(host);
            self.status =
                "这台音响已有配对凭据。重新配对成功后才替换旧凭据；失败、超时或取消都保留旧凭据。"
                    .into();
            return;
        }
        self.repair_confirm = None;
        self.busy = true;
        self.activity = "pairing";
        self.status = "正在请求音响显示 PIN…".into();
        let tx = self.events.clone();
        thread::spawn(move || {
            let work = (|| -> Result<(), Box<dyn std::error::Error>> {
                let (ip, port) = super::host_port(&host)?;
                let mut channel = ControlChannel::builder(ip).port(port).connect()?;
                channel.hap_pin_start()?;
                let (pin_tx, pin_rx) = mpsc::channel();
                tx.send(Event::PairPin(pin_tx))?;
                let pin = pin_rx.recv_timeout(Duration::from_secs(90))?;
                let credential = channel.hap_pair_setup_shown_pin(pin.trim(), &mut OsRng)?;
                // The old credential is replaced only after pair-setup succeeded.
                super::vault::save(&host, &credential.to_storage_string(), had)?;
                Ok(())
            })();
            let msg = match work {
                Ok(()) if had => "重新配对完成，已替换旧凭据。".to_owned(),
                Ok(()) => "配对完成，凭据已使用 Windows 当前用户加密保存。".to_owned(),
                Err(error) => pair_failure_text(error.as_ref(), had),
            };
            let _ = tx.send(Event::WorkerDone(msg));
        });
    }
    /// Python-version credentials, only on request; needs scanned deviceids.
    fn import_legacy(&mut self) {
        let rows: Vec<(String, String)> = self
            .speakers
            .iter()
            .filter_map(|s| Some((s.address.clone(), s.id.clone()?)))
            .collect();
        if rows.is_empty() {
            self.status = "请先扫描音响：导入旧版凭据需要音响的设备标识。".into();
            return;
        }
        self.status = match super::vault::import_python(&rows) {
            Ok((0, 0)) => "旧版凭据中没有与已扫描音响对应的配对凭据。".into(),
            Ok((imported, skipped)) => format!(
                "已导入 {imported} 台音响的旧版配对凭据，跳过 {skipped} 台（已有凭据或旧凭据不可用）。"
            ),
            Err(error) => format!("{error}，未导入。"),
        };
    }
    fn set_host(&mut self, host: String) {
        if host != self.host {
            self.repair_confirm = None;
        }
        self.host = host;
    }
}
impl Drop for App {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.save_settings();
    }
}
impl App {
    /// Saved after each calibration, test end and stop, not only on exit, so
    /// a crash or forced exit does not lose calibrated values.
    fn save_settings(&mut self) {
        // Tests must never touch the user's real settings file.
        if !cfg!(test) {
            self.save_with(crate::settings::save);
        }
    }
    fn save_with(&mut self, save: impl FnOnce(&crate::settings::Settings) -> Result<(), String>) {
        // A settings file that could not be read is never replaced by defaults.
        if self.save_blocked {
            return;
        }
        let settings = self.settings_snapshot();
        match save(&settings) {
            Ok(()) => {
                self.saved_json = serde_json::to_string(&settings).unwrap_or_default();
                self.dirty_since = None;
            }
            Err(error) => self.note_save_failure(&error),
        }
    }
    /// A failing save is retried about every 30 s, not on every tick, and is
    /// shown once in the status.
    fn note_save_failure(&mut self, error: &str) {
        crate::diagnostics::record_error(&format!("设置保存失败：{error}"));
        // elapsed() of a future instant is zero, so autosave waits 29 + 1 s.
        self.dirty_since = Some(Instant::now() + Duration::from_secs(29));
        if !self.status.contains("设置保存失败") {
            self.status = format!("{} 设置保存失败：{error}", self.status);
        }
    }
    fn settings_json(&self) -> String {
        serde_json::to_string(&self.settings_snapshot()).unwrap_or_default()
    }
    /// Any edit (delay, trim, volume, channel, buffer, ...) is written about a
    /// second later, so a crash or forced exit loses at most that second.
    fn autosave(&mut self) {
        if self.settings_json() == self.saved_json {
            self.dirty_since = None;
        } else if self.dirty_since.get_or_insert_with(Instant::now).elapsed()
            >= Duration::from_secs(1)
        {
            self.save_settings();
        }
    }
    fn settings_snapshot(&self) -> crate::settings::Settings {
        let mut settings = crate::settings::Settings {
            linear_master: true,
            master: self.volume_ui,
            input: Some(self.input_name.clone())
                .filter(|n| !n.is_empty())
                .or_else(|| self.devices.get(self.selected).cloned())
                .unwrap_or_default(),
            microphone: Some(self.mic_name.clone())
                .filter(|n| !n.is_empty())
                .or_else(|| self.microphones.get(self.mic_selected).cloned())
                .unwrap_or_default(),
            test_volume: self.test_volume,
            reconnect: self.reconnect,
            buffer_ms: self.buffer_ms,
            theme: self.theme.clone(),
            routes: Default::default(),
            pairs: true,
        };
        for speaker in &self.speakers {
            if let Some(r) = self.routes.get(&speaker.address) {
                settings.routes.insert(
                    speaker.address.clone(),
                    crate::settings::SavedRoute {
                        name: speaker.name.clone(),
                        enabled: r.selected,
                        mode: r.mode,
                        delay: r.delay,
                        volume: r.volume,
                        offset: 0,
                        trim: r.trim,
                        id: speaker.id.clone().unwrap_or_default(),
                        partner: r.partner.clone().unwrap_or_default(),
                        home_pair: speaker.pair.clone().unwrap_or_default(),
                    },
                );
            }
        }
        settings
    }

    /// A speaker found at a new IPv4 address keeps its row, calibration and
    /// pairing, matched by TXT `deviceid`; never while a session uses the rows.
    /// Of the announced addresses, one that already has this device's row (or
    /// a manual row) wins, so a speaker with several IPv4 addresses stays put.
    fn on_found(&mut self, mut s: Speaker, addresses: Vec<String>) {
        let row_at = |a: &String, id: Option<&str>| {
            self.speakers
                .iter()
                .any(|v| v.address == *a && v.id.as_deref() == id)
        };
        let id = s.id.as_deref();
        let other_device = |a: &&String| {
            self.speakers
                .iter()
                .any(|v| v.address == **a && v.id.is_some() && v.id.as_deref() != id)
        };
        let Some(pick) = id
            .and_then(|id| self.scan_seen.get(id))
            .filter(|a| addresses.contains(a))
            .or_else(|| id.and_then(|id| addresses.iter().find(|a| row_at(a, Some(id)))))
            .or_else(|| addresses.iter().find(|a| row_at(a, None)))
            .or_else(|| addresses.iter().find(|a| !other_device(a)))
            .or(addresses.first())
            .cloned()
        else {
            return;
        };
        s.address = pick;
        if let Some(id) = s.id.clone() {
            match self.scan_seen.get(&id) {
                // A later resolution of the same device in this scan: keep the first.
                Some(first) if *first != s.address => return,
                _ => {
                    self.scan_seen.insert(id.clone(), s.address.clone());
                }
            }
            if !row_at(&s.address, Some(&id))
                && let Some(old) = self
                    .speakers
                    .iter()
                    .position(|v| v.id.as_deref() == Some(id.as_str()))
            {
                if self.busy {
                    self.status = format!(
                        "「{}」的地址已变为 {}，停止播放后重新扫描以更新。",
                        s.name, s.address
                    );
                    return;
                }
                let from = self.speakers[old].address.clone();
                self.move_route(&from, &s.address);
                self.speakers[old].address = s.address.clone();
            }
        }
        let (kept, name, id) = (s.address.clone(), s.name.clone(), s.id.clone());
        if let Some(existing) = self.speakers.iter_mut().find(|v| v.address == s.address) {
            existing.name = s.name;
            if s.id.is_some() {
                existing.id = s.id;
            }
            existing.pair = s.pair;
            existing.password = s.password;
        } else {
            self.routes
                .entry(s.address.clone())
                .or_insert_with(RouteUi::new);
            self.speakers.push(s);
        }
        // A leftover row of this device on another of its addresses is removed
        // only when it holds nothing; calibrations are never merged. During a
        // session the next scan after it decides, so its status stays.
        if self.busy {
            return;
        }
        let leftovers: Vec<String> = self
            .speakers
            .iter()
            .filter(|v| {
                v.address != kept
                    && addresses.contains(&v.address)
                    && (v.id.is_none() || v.id == id)
            })
            .map(|v| v.address.clone())
            .collect();
        for dupe in leftovers {
            // Tests must never touch the user's real credential files.
            let paired = !cfg!(test) && crate::vault::exists(&dupe);
            if !paired
                && !self.session_routes.contains(&dupe)
                && self.routes.get(&dupe).is_none_or(RouteUi::is_default)
            {
                let selected = self.routes.remove(&dupe).is_some_and(|r| r.selected);
                self.speakers.retain(|v| v.address != dupe);
                if let Some(route) = self.routes.get_mut(&kept) {
                    route.selected |= selected;
                }
                if self.host == dupe {
                    self.set_host(kept.clone());
                }
            } else {
                self.status = format!("「{name}」在 {kept} 和 {dupe} 各有一行设置，请只勾选一行。");
            }
        }
    }

    /// Whatever occupied the new address moves to the old one; its own device,
    /// if any, is matched again when found at its new address.
    fn move_route(&mut self, from: &str, to: &str) {
        let moved = self.routes.remove(from);
        let displaced = self.routes.remove(to);
        if let Some(route) = moved {
            self.routes.insert(to.into(), route);
        }
        if let Some(route) = displaced {
            self.routes.insert(from.into(), route);
        }
        // Stereo partners follow the swap of the two addresses.
        for route in self.routes.values_mut() {
            match route.partner.as_deref() {
                Some(p) if p == from => route.partner = Some(to.into()),
                Some(p) if p == to => route.partner = Some(from.into()),
                _ => {}
            }
        }
        if let Some(v) = self.speakers.iter_mut().find(|v| v.address == to) {
            v.address = from.into();
        }
        if self.host == from {
            self.set_host(to.into());
        } else if self.host == to {
            self.set_host(from.into());
        }
        // Tests must never touch the user's real credential files.
        let swapped = if cfg!(test) {
            Ok(())
        } else {
            crate::vault::swap(from, to)
        };
        match swapped {
            Ok(()) => self.status = format!("音响地址已从 {from} 更新为 {to}，设置与配对已保留。"),
            Err(error) => {
                self.status = format!("音响地址已更新为 {to}，但配对凭据未能迁移：{error}")
            }
        }
        self.save_settings();
    }
}

/* ---------- stereo pairs ---------- */
impl App {
    fn name_of(&self, address: &str) -> String {
        self.speakers
            .iter()
            .find(|s| s.address == address)
            .map_or_else(|| address.to_owned(), |s| s.name.clone())
    }
    /// Drops links that do not join one left and one right speaker pointing
    /// at each other. With `migrate` (settings from before pairs existed),
    /// exactly one left and one right speaker become that pair.
    fn repair_pairs(&mut self, migrate: bool) {
        let valid: Vec<(String, Option<String>)> = self
            .routes
            .iter()
            .map(|(address, route)| {
                let partner = route.partner.clone().filter(|p| {
                    self.routes.get(p).is_some_and(|other| {
                        other.partner.as_deref() == Some(address.as_str())
                            && route.mode * other.mode == 2
                    })
                });
                (address.clone(), partner)
            })
            .collect();
        for (address, partner) in valid {
            self.routes.get_mut(&address).unwrap().partner = partner;
        }
        if migrate && self.routes.values().all(|r| r.partner.is_none()) {
            let side = |mode: u32| -> Vec<String> {
                self.routes
                    .iter()
                    .filter(|(_, r)| r.mode == mode)
                    .map(|(a, _)| a.clone())
                    .collect()
            };
            if let ([left], [right]) = (side(1).as_slice(), side(2).as_slice()) {
                let (left, right) = (left.clone(), right.clone());
                self.routes.get_mut(&left).unwrap().partner = Some(right.clone());
                self.routes.get_mut(&right).unwrap().partner = Some(left);
            }
        }
    }
    /// Both speakers of a pair play, or neither: half a stereo image is not useful.
    fn set_selected(&mut self, address: &str, on: bool) {
        let Some(route) = self.routes.get_mut(address) else {
            return;
        };
        route.selected = on;
        if let Some(partner) = route.partner.clone()
            && let Some(other) = self.routes.get_mut(&partner)
        {
            other.selected = on;
        }
    }
    fn unpair(&mut self, address: &str) {
        let Some(partner) = self.routes.get_mut(address).and_then(|r| r.partner.take()) else {
            return;
        };
        self.last_result = None;
        self.routes.get_mut(address).unwrap().set_mode(0);
        if let Some(other) = self.routes.get_mut(&partner) {
            other.partner = None;
            other.set_mode(0);
        }
    }
    fn make_pair(&mut self, left: &str, right: &str) {
        if left == right || !self.routes.contains_key(left) || !self.routes.contains_key(right) {
            return;
        }
        for address in [left, right] {
            if self.routes[address].partner.is_some() {
                self.unpair(address);
            }
        }
        self.last_result = None;
        let on = self.routes[left].selected || self.routes[right].selected;
        for (address, mode, partner) in [(left, 1, right), (right, 2, left)] {
            let route = self.routes.get_mut(address).unwrap();
            route.set_mode(mode);
            route.partner = Some(partner.into());
            route.selected = on;
        }
        self.status = format!(
            "「{}」与「{}」已组成立体声对：左、右声道。",
            self.name_of(left),
            self.name_of(right)
        );
    }
    fn swap_pair(&mut self, address: &str) {
        let Some(partner) = self.routes.get(address).and_then(|r| r.partner.clone()) else {
            return;
        };
        self.last_result = None;
        let (a, b) = (self.routes[address].mode, self.routes[&partner].mode);
        self.routes.get_mut(address).unwrap().set_mode(b);
        self.routes.get_mut(&partner).unwrap().set_mode(a);
        self.status = "已互换左右声道。".into();
    }
    /// Stereo and mono end a pair; left or right keep it, with the partner
    /// moved to the other side.
    fn set_route_mode(&mut self, address: &str, mode: u32) {
        let Some(route) = self.routes.get_mut(address) else {
            return;
        };
        match (route.partner.clone(), mode) {
            (Some(_), 0 | 3) => {
                self.unpair(address);
                self.routes.get_mut(address).unwrap().set_mode(mode);
            }
            (Some(partner), 1 | 2) => {
                route.set_mode(mode);
                if let Some(other) = self.routes.get_mut(&partner) {
                    other.set_mode(3 - mode);
                }
            }
            (None, 0..=3) => route.set_mode(mode),
            _ => {}
        }
    }
}

/* ---------- page commands and the state snapshot ---------- */
impl App {
    fn command(&mut self, body: &str) {
        let Ok(command) = serde_json::from_str::<Command>(body) else {
            crate::diagnostics::record_error("界面命令格式无效");
            return;
        };
        let editable = !self.measuring && self.transition.is_none();
        match command {
            Command::Ready => self.pushed.clear(),
            Command::Scan => self.scan(),
            Command::RefreshInputs => self.refresh_inputs(),
            Command::RefreshMics => self.refresh_mics(),
            Command::OpenMixer => {
                let _ = std::process::Command::new("explorer.exe")
                    .arg("ms-settings:apps-volume")
                    .spawn();
            }
            Command::OpenDriverPage => {
                let _ = std::process::Command::new("explorer.exe")
                    .arg("https://vb-audio.com/Cable/")
                    .spawn();
                self.status = "已在浏览器打开 VB-CABLE 官方下载页；安装后点击「刷新」。".into();
            }
            // Read-only, so also allowed while busy.
            Command::ExportDiagnostics => self.export_diagnostics(),
            Command::AddHost => match super::host_port(self.host.trim()) {
                Ok((ip, port)) => {
                    let address = format!("{ip}:{port}");
                    if !self.speakers.iter().any(|s| s.address == address) {
                        self.speakers.push(Speaker {
                            name: "手动添加".into(),
                            address: address.clone(),
                            ..Default::default()
                        });
                        self.routes
                            .entry(address.clone())
                            .or_insert_with(RouteUi::new);
                    }
                    self.host = address;
                }
                Err(_) => self.status = "请输入有效的 IPv4 地址。".into(),
            },
            Command::Start => self.start(false),
            Command::Tone => self.start(true),
            Command::Stop => {
                self.stop.store(true, Ordering::Release);
                self.pin_sender.take();
                self.repair_confirm = None;
            }
            Command::PairDevice { replace } => self.pair_device(replace),
            Command::CancelPair => {
                if self.repair_confirm.take().is_some() {
                    self.status = "已取消重新配对，旧凭据未更改。".into();
                }
            }
            Command::ImportLegacyCredentials if !self.busy => self.import_legacy(),
            Command::ToggleTest => self.toggle_test(),
            Command::Measure => self.calibrate(),
            Command::SetDevice { index } if index < self.devices.len() => {
                self.selected = index;
                self.input_name = self.devices[index].clone();
            }
            Command::SetMic { index } if index < self.microphones.len() => {
                self.mic_selected = index;
                self.mic_name = self.microphones[index].clone();
            }
            Command::SetMaster { value } if editable => {
                self.volume_ui = value.min(100);
                self.update_gains();
            }
            Command::SetTestVolume { value }
                if !self.measuring && !self.transition.is_some_and(|(_, starting)| !starting) =>
            {
                self.test_volume = value.min(100);
                self.update_gains();
                if self.test_mode.load(Ordering::Acquire) == 1 {
                    self.transition = Some((Instant::now() + Duration::from_secs(5), true));
                    self.status = "测试音量已更新，等待播放缓冲；稳定后可测量。".into();
                }
            }
            Command::SetBuffer { value } if !self.busy => {
                self.buffer_ms = (value.clamp(300, 2000) + 25) / 50 * 50;
            }
            Command::SetReconnect { on } if !self.busy => self.reconnect = on,
            Command::SetTheme { theme }
                if matches!(theme.as_str(), "light" | "dark" | "system") =>
            {
                self.theme = theme
            }
            Command::Route {
                address,
                selected,
                mode,
                delay,
                trim,
                volume,
            } if editable && self.routes.contains_key(&address) => {
                if let Some(on) = selected {
                    self.set_selected(&address, on);
                }
                if let Some(mode) = mode {
                    self.set_route_mode(&address, mode);
                }
                let test_idle = self.test_mode.load(Ordering::Acquire) == 0;
                let route = self.routes.get_mut(&address).unwrap();
                let before = (route.delay, route.trim);
                if let Some(delay) = delay.filter(|v| v.is_finite()) {
                    route.delay = (delay.clamp(0.0, 2000.0) * 10.0).round() / 10.0;
                    route
                        .control
                        .delay_us
                        .store(delay_us(route.delay), Ordering::Release);
                }
                if let Some(trim) = trim.filter(|v| v.is_finite()) {
                    // `+ 0.0` turns -0.0 into 0.0 for display.
                    route.trim = (trim.clamp(-24.0, 0.0) * 10.0).round() / 10.0 + 0.0;
                    route
                        .control
                        .trim_db
                        .store((route.trim as f32).to_bits(), Ordering::Release);
                }
                if let Some(volume) = volume
                    && test_idle
                {
                    route.volume = volume.min(100);
                    route.control.volume.store(route.volume, Ordering::Release);
                }
                // Values that were never measured must not show as aligned.
                if (route.delay, route.trim) != before {
                    self.last_result = None;
                }
            }
            Command::MakePair { left, right } if editable => self.make_pair(&left, &right),
            Command::Unpair { address } if editable => {
                self.unpair(&address);
                self.status = "已拆分立体声对，两台恢复为立体声。".into();
            }
            Command::SwapPair { address } if editable => self.swap_pair(&address),
            Command::SetTarget { address } if self.routes.contains_key(&address) => {
                self.set_host(address)
            }
            Command::SetHost { host } => self.set_host(host.trim().chars().take(64).collect()),
            Command::SubmitPin { pin } => {
                if pin.len() == 4 && pin.bytes().all(|b| b.is_ascii_digit()) {
                    if let Some(sender) = self.pin_sender.take() {
                        let _ = sender.send(pin);
                    }
                } else {
                    self.status = "PIN 必须为四位数字。".into();
                }
            }
            _ => {}
        }
    }

    /// Worker events, the end of a buffer transition, and saving.
    fn tick(&mut self) {
        while let Ok(event) = self.receiver.try_recv() {
            match event {
                Event::Found(s, addresses) => self.on_found(s, addresses),
                Event::ScanDone => self.scanning = false,
                Event::PairPin(tx) => {
                    self.pin_sender = Some(tx);
                    self.status = "请在下方输入音响显示的 PIN。".into();
                }
                Event::Message(s) => self.status = s,
                Event::Connected(s) => {
                    self.connected = true;
                    self.connected_at = Some(Instant::now());
                    self.status = if self.start_notice.is_empty() {
                        s
                    } else {
                        format!("{s} {}", self.start_notice)
                    };
                }
                Event::Reconnecting(s) => {
                    self.connected = false;
                    self.measuring = false;
                    // The new connection has to be measured again.
                    self.last_result = None;
                    self.transition = None;
                    self.test_mode.store(0, Ordering::Release);
                    for id in &self.session_routes {
                        if let Some(r) = self.routes.get(id) {
                            r.control.volume.store(r.volume, Ordering::Release);
                        }
                    }
                    self.status = s;
                }
                Event::WorkerDone(s) => {
                    self.busy = false;
                    self.connected = false;
                    self.measuring = false;
                    self.transition = None;
                    self.test_mode.store(0, Ordering::Release);
                    self.pin_sender = None;
                    self.repair_confirm = None;
                    let involved = if self.session_routes.is_empty() {
                        vec![self.host.trim().to_owned()]
                    } else {
                        self.session_routes.clone()
                    };
                    self.status = if password_hint(&s, &self.speakers, &involved) {
                        format!(
                            "{s} 此音响开启了连接密码，当前版本暂不支持；可在家庭 App 调整访问设置。"
                        )
                    } else {
                        s
                    };
                    self.save_settings();
                }
                Event::Measured(mode, ids, result) => {
                    if !Arc::ptr_eq(&mode, &self.test_mode)
                        || !self.connected
                        || mode.load(Ordering::Acquire) != 1
                    {
                        continue;
                    }
                    self.measuring = false;
                    match result {
                        Ok((dl, dr, tl, tr, ms, db)) => {
                            self.last_result = Some((ms, db));
                            for (id, delay, trim) in [(&ids[0], dl, tl), (&ids[1], dr, tr)] {
                                if let Some(r) = self.routes.get_mut(id) {
                                    r.delay = delay;
                                    r.trim = trim;
                                    r.control.delay_us.store(delay_us(delay), Ordering::Release);
                                    r.control
                                        .trim_db
                                        .store((trim as f32).to_bits(), Ordering::Release);
                                }
                            }
                            self.status = format!(
                                "测得右侧比左侧晚 {ms:+.2} ms、响 {db:+.1} dB；已立即应用：延迟左 {dl:.1}、右 {dr:.1} ms，电平修正左 {tl:+.1}、右 {tr:+.1} dB。"
                            );
                            // New delays and trims reach the speakers after the
                            // send queue and receiver buffer; re-measure after that.
                            self.measured = true;
                            self.transition = Some((Instant::now() + Duration::from_secs(5), true));
                            self.save_settings();
                        }
                        Err(error) => self.status = format!("测量失败：{error}。未应用结果。"),
                    }
                }
            }
        }
        for host in crate::event_pump::take_volume_changes() {
            // Warn only: re-applying would fight a level the listener just chose.
            if self.busy {
                self.status = format!(
                    "「{}」的音量在外部被修改（触控、Siri 或家庭 App），左右平衡可能已改变，建议重新校准。",
                    self.name_of(&host)
                );
            }
        }
        if self.connected
            && self
                .transition
                .is_some_and(|(until, _)| Instant::now() >= until)
        {
            let (_, starting) = self.transition.take().unwrap();
            if starting && self.measured {
                self.measured = false;
                self.status.push_str(" 已稳定，可再次测量验证。");
            } else if starting {
                self.status = "连续测试音已开启；两台使用相同测试电平。".into();
            } else {
                self.test_mode.store(0, Ordering::Release);
                self.status = "连续测试已结束，恢复应用声音。".into();
            }
        }
        self.autosave();
    }

    /// Settling after connect, the 5 s buffer drain, or the measurement itself.
    fn progress(&self) -> Option<(f32, String)> {
        let left = |remaining: Duration| remaining.as_secs() + 1;
        if let Some((until, starting)) = self.transition {
            let remaining = until.saturating_duration_since(Instant::now());
            let what = if starting {
                "等待播放缓冲排空"
            } else {
                "正在恢复播放音量"
            };
            return Some((
                1.0 - remaining.as_secs_f32() / 5.0,
                format!("{what} · 剩 {} 秒", left(remaining)),
            ));
        }
        if self.measuring {
            let elapsed = self
                .measuring_since
                .map_or(Duration::ZERO, |at| at.elapsed());
            let remaining = MEASURE_TIME.saturating_sub(elapsed);
            return Some((
                (elapsed.as_secs_f32() / MEASURE_TIME.as_secs_f32()).min(0.97),
                format!("正在测量延迟和音量，请保持安静 · 约 {} 秒", left(remaining)),
            ));
        }
        let settled = self
            .connected_at
            .map_or(SETTLE_AFTER_CONNECT, |at| at.elapsed());
        (self.connected
            && self.test_mode.load(Ordering::Acquire) == 1
            && settled < SETTLE_AFTER_CONNECT)
            .then(|| {
                (
                    settled.as_secs_f32() / SETTLE_AFTER_CONNECT.as_secs_f32(),
                    format!(
                        "同步稳定中 · 剩 {} 秒",
                        left(SETTLE_AFTER_CONNECT - settled)
                    ),
                )
            })
    }

    fn state_json(&self) -> String {
        let test_mode = self.test_mode.load(Ordering::Acquire);
        // The pair calibration measures: the running session, else what is ticked.
        let candidates: Vec<&String> = if self.busy {
            self.session_routes.iter().collect()
        } else {
            self.speakers
                .iter()
                .map(|s| &s.address)
                .filter(|a| self.routes.get(*a).is_some_and(|r| r.selected))
                .collect()
        };
        let side = |mode: u32| {
            candidates
                .iter()
                .find(|a| self.routes.get(**a).is_some_and(|r| r.mode == mode))
                .map(|a| (*a).clone())
        };
        let (left, right) = (side(1), side(2));
        let speakers: Vec<_> = self
            .speakers
            .iter()
            .filter_map(|s| {
                let r = self.routes.get(&s.address)?;
                Some(json!({
                    "address": s.address,
                    "name": s.name,
                    "selected": r.selected,
                    "mode": r.mode,
                    "delay": r.delay,
                    "trim": r.trim,
                    "volume": r.volume,
                    "level": level_text(r.volume, r.trim, self.volume_ui),
                    "partner": r.partner,
                    "homePair": s.pair,
                    "needsPassword": s.password,
                    "target": self.host == s.address,
                }))
            })
            .collect();
        let editable = !self.measuring && self.transition.is_none();
        json!({
            "run": self.run_state(),
            "busy": self.busy,
            "connected": self.connected,
            "measuring": self.measuring,
            "scanning": self.scanning,
            "testMode": test_mode,
            "transition": self.transition.is_some(),
            "status": self.status,
            "master": self.volume_ui,
            "testVolume": self.test_volume,
            "bufferMs": self.buffer_ms,
            "reconnect": self.reconnect,
            "theme": self.theme,
            "devices": self.devices,
            "device": self.selected,
            "mics": self.microphones,
            "mic": self.mic_selected,
            "host": self.host,
            "pinRequested": self.pin_sender.is_some(),
            "repairConfirm": self.repair_confirm.is_some() && !self.busy,
            "cpu": self.cpu_label,
            "webview": self.webview_label,
            "progress": self.progress().map(|(fraction, label)| json!({ "fraction": fraction, "label": label })),
            "lastResult": self.last_result.map(|(ms, db)| json!({ "ms": ms, "db": db })),
            // Whole dB: the meter is a sign of life, and it keeps pushes at the tick rate.
            "inputLevel": self.connected.then(|| crate::multistream::input_level().round()),
            "droppedPackets": super::DROPPED_PACKETS.load(Ordering::Relaxed),
            "checks": {
                "pair": candidates.len() == 2 && left.is_some() && right.is_some(),
                "mic": !self.microphones.is_empty(),
            },
            "calPair": { "left": left, "right": right },
            "session": self.session_routes,
            "speakers": speakers,
            "editable": editable,
            "volumeEditable": test_mode == 0,
            "masterEditable": editable,
            "testVolumeEditable": !self.measuring && !self.transition.is_some_and(|(_, starting)| !starting),
        })
        .to_string()
    }
    fn run_state(&self) -> &'static str {
        if self.connected {
            "live"
        } else if self.busy {
            self.activity
        } else {
            "idle"
        }
    }
    /// What the export writes above the logs: no speaker ids, tsids or credentials.
    fn diagnostics_report(&self) -> String {
        let mut settings = self.settings_snapshot();
        for route in settings.routes.values_mut() {
            route.id.clear();
            route.home_pair.clear();
        }
        let speakers: Vec<_> = self
            .speakers
            .iter()
            .map(|s| json!({ "name": s.name, "address": s.address, "homePair": s.pair.is_some() }))
            .collect();
        serde_json::to_string_pretty(&json!({
            "app": "合鸣 Duetto",
            "version": env!("CARGO_PKG_VERSION"),
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "cpu": self.cpu_label,
            "webview": self.webview_label,
            "run": self.run_state(),
            "status": self.status,
            "droppedPackets": super::DROPPED_PACKETS.load(Ordering::Relaxed),
            "inputs": self.devices,
            "mics": self.microphones,
            "settings": settings,
            "speakers": speakers,
            "note": "包含音响名称、IP 地址和输入设备名称；不包含配对凭据、PIN、密码或音频内容。",
        }))
        .unwrap_or_default()
    }
    fn export_diagnostics(&mut self) {
        let report = self.diagnostics_report();
        // Tests never write under the real LOCALAPPDATA or open Explorer.
        if cfg!(test) {
            return;
        }
        match crate::diagnostics::export(&report) {
            Ok(path) => {
                use std::os::windows::process::CommandExt;
                // Explorer exits with 1 even when it opened the folder.
                let _ = std::process::Command::new("explorer.exe")
                    .raw_arg(format!("/select,\"{}\"", path.display()))
                    .spawn();
                self.status = format!("诊断已导出：{}", path.display());
            }
            Err(error) => self.status = format!("诊断导出失败：{error}"),
        }
    }
    /// The snapshot, only when it differs from the last one sent.
    fn take_state(&mut self) -> Option<String> {
        let state = self.state_json();
        if state == self.pushed {
            return None;
        }
        self.pushed = state.clone();
        Some(state)
    }
    fn shutdown(&mut self) {
        self.stop.store(true, Ordering::Release);
        // Dropping the sender ends a pairing worker waiting for its PIN.
        self.pin_sender = None;
        if self.busy {
            // Give the session time to send TEARDOWN before the process exits.
            let deadline = Instant::now() + Duration::from_secs(3);
            while let Some(left) = deadline.checked_duration_since(Instant::now()) {
                match self.receiver.recv_timeout(left) {
                    Ok(Event::WorkerDone(_)) | Err(_) => break,
                    // A PairPin sender is dropped here, which also ends that worker.
                    Ok(_) => {}
                }
            }
        }
        self.save_settings();
    }
}

fn cpu_compatibility_label() -> String {
    #[cfg(target_arch = "x86_64")]
    {
        // x86-64 guarantees SSE2 on both Intel and AMD processors; vendor is
        // read only for a clear on-device compatibility check in the UI.
        let id = std::arch::x86_64::__cpuid(0);
        let vendor = [id.ebx, id.edx, id.ecx]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>();
        cpu_compatibility_from_vendor(&vendor)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        "非 x86-64".to_owned()
    }
}

fn cpu_compatibility_from_vendor(vendor: &[u8]) -> String {
    match vendor {
        b"GenuineIntel" => "Intel x64 · SSE2".to_owned(),
        b"AuthenticAMD" => "AMD x64 · SSE2".to_owned(),
        _ => "x86-64 · SSE2".to_owned(),
    }
}

/* ---------- the window ---------- */
/// The page and its libraries are compiled in; nothing is read from disk or the network.
fn asset(path: &str) -> Option<(&'static [u8], &'static str)> {
    Some(match path {
        "/" | "/index.html" => (
            &include_bytes!("../web/index.html")[..],
            "text/html; charset=utf-8",
        ),
        "/app.css" => (
            &include_bytes!("../web/app.css")[..],
            "text/css; charset=utf-8",
        ),
        "/app.js" => (
            &include_bytes!("../web/app.js")[..],
            "text/javascript; charset=utf-8",
        ),
        "/vendor/gsap.min.js" => (
            &include_bytes!("../web/vendor/gsap.min.js")[..],
            "text/javascript",
        ),
        "/vendor/Flip.min.js" => (
            &include_bytes!("../web/vendor/Flip.min.js")[..],
            "text/javascript",
        ),
        "/vendor/SplitText.min.js" => (
            &include_bytes!("../web/vendor/SplitText.min.js")[..],
            "text/javascript",
        ),
        "/vendor/MotionPathPlugin.min.js" => (
            &include_bytes!("../web/vendor/MotionPathPlugin.min.js")[..],
            "text/javascript",
        ),
        "/vendor/DrawSVGPlugin.min.js" => (
            &include_bytes!("../web/vendor/DrawSVGPlugin.min.js")[..],
            "text/javascript",
        ),
        "/fonts/NotoSansSC-GB2312.woff2" => (
            &include_bytes!("../web/fonts/NotoSansSC-GB2312.woff2")[..],
            "font/woff2",
        ),
        _ => return None,
    })
}
fn asset_response(path: &str) -> wry::http::Response<std::borrow::Cow<'static, [u8]>> {
    let builder = wry::http::Response::builder();
    match asset(path) {
        Some((body, mime)) => builder
            .header(wry::http::header::CONTENT_TYPE, mime)
            .body(body.into()),
        None => builder.status(404).body(Vec::new().into()),
    }
    .expect("static response")
}

fn window_theme(theme: &str) -> Option<tao::window::Theme> {
    match theme {
        "light" => Some(tao::window::Theme::Light),
        "dark" => Some(tao::window::Theme::Dark),
        _ => None,
    }
}

fn app_icon() -> Option<tao::window::Icon> {
    let pixels = image::load_from_memory(include_bytes!("../assets/airbridge-256.png"))
        .ok()?
        .to_rgba8();
    let (width, height) = pixels.dimensions();
    tao::window::Icon::from_rgba(pixels.into_raw(), width, height).ok()
}

/// Only the embedded page may be shown or send commands.
fn allowed_url(url: &str) -> bool {
    url.starts_with("http://duetto.localhost/")
}

/// An exclusive handle: a second GUI instance fails with ERROR_SHARING_VIOLATION (32).
/// Windows releases it when the process exits or crashes, so it never goes stale.
fn instance_lock(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .share_mode(0)
        .open(path)
}

fn show_message(text: &str) {
    let text: Vec<u16> = text.encode_utf16().chain(Some(0)).collect();
    let title: Vec<u16> = "合鸣 Duetto".encode_utf16().chain(Some(0)).collect();
    unsafe {
        use windows_sys::Win32::UI::WindowsAndMessaging::{MB_ICONINFORMATION, MB_OK, MessageBoxW};
        MessageBoxW(
            std::ptr::null_mut(),
            text.as_ptr(),
            title.as_ptr(),
            MB_OK | MB_ICONINFORMATION,
        );
    }
}

pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    use tao::{
        dpi::LogicalSize,
        event::{Event as WindowLoopEvent, WindowEvent},
        event_loop::{ControlFlow, EventLoopBuilder},
        window::WindowBuilder,
    };
    let data = std::env::var_os("LOCALAPPDATA")
        .map(|base| std::path::PathBuf::from(base).join("AirBridge-Rust"));
    // Two instances would overwrite each other's settings and drive the same speakers.
    let lock = match &data {
        Some(dir) => {
            let _ = std::fs::create_dir_all(dir);
            match instance_lock(&dir.join("instance.lock")) {
                Err(e) if e.raw_os_error() == Some(32) => {
                    show_message("合鸣 Duetto 已在运行，请切换到已打开的窗口。");
                    return Err("合鸣 Duetto 已在运行".into());
                }
                // Any other failure (e.g. a read-only folder) must not block the app.
                lock => lock.ok(),
            }
        }
        None => None,
    };
    let mut app = App::new();
    let event_loop = EventLoopBuilder::<String>::with_user_event().build();
    let proxy = event_loop.create_proxy();
    let window = WindowBuilder::new()
        .with_title("合鸣 Duetto")
        .with_inner_size(LogicalSize::new(1180.0, 800.0))
        .with_min_inner_size(LogicalSize::new(960.0, 640.0))
        .with_window_icon(app_icon())
        .with_theme(window_theme(&app.theme))
        .build(&event_loop)?;
    // The first frame already has the right ground: no white flash in dark mode.
    let dark = window.theme() == tao::window::Theme::Dark;
    // Browser data lives with the settings, not beside a possibly read-only EXE.
    let mut context = wry::WebContext::new(data.map(|dir| dir.join("WebView2")));
    let webview = wry::WebViewBuilder::new_with_web_context(&mut context)
        .with_custom_protocol("duetto".into(), |_, request| {
            asset_response(request.uri().path())
        })
        .with_url("http://duetto.localhost/index.html")
        // A dropped file or link must not replace the UI; it would also get IPC access.
        .with_navigation_handler(|url| allowed_url(&url))
        .with_new_window_req_handler(|_, _| wry::NewWindowResponse::Deny)
        .with_initialization_script(format!(
            "document.documentElement.dataset.theme = {};",
            json!(if dark { "dark" } else { "light" })
        ))
        .with_background_color(if dark {
            (11, 13, 16, 255)
        } else {
            (243, 244, 246, 255)
        })
        .with_ipc_handler(move |request| {
            if allowed_url(&request.uri().to_string()) {
                let _ = proxy.send_event(request.into_body());
            }
        })
        .build(&window)?;
    event_loop.run(move |event, _, control_flow| {
        // Both must live as long as the window: the context backs the webview.
        let _ = (&lock, &context);
        *control_flow = ControlFlow::WaitUntil(Instant::now() + Duration::from_millis(100));
        match event {
            WindowLoopEvent::UserEvent(body) => {
                let theme = app.theme.clone();
                app.command(&body);
                if app.theme != theme {
                    window.set_theme(window_theme(&app.theme));
                }
            }
            WindowLoopEvent::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => {
                // Hidden first: the shutdown wait must not look like a hang.
                window.set_visible(false);
                app.shutdown();
                *control_flow = ControlFlow::Exit;
                return;
            }
            _ => {}
        }
        app.tick();
        if let Some(state) = app.take_state() {
            let _ =
                webview.evaluate_script(&format!("window.duetto && window.duetto.update({state})"));
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_compatibility_identifies_both_x64_vendors() {
        assert_eq!(
            cpu_compatibility_from_vendor(b"GenuineIntel"),
            "Intel x64 · SSE2"
        );
        assert_eq!(
            cpu_compatibility_from_vendor(b"AuthenticAMD"),
            "AMD x64 · SSE2"
        );
    }

    fn start_fixture() -> App {
        let (events, receiver) = mpsc::channel();
        App {
            events,
            receiver,
            devices: vec!["test-capture-must-not-open".into()],
            selected: 0,
            input_name: String::new(),
            mic_name: String::new(),
            speakers: Vec::new(),
            routes: HashMap::new(),
            host: String::new(),
            pin_sender: None,
            repair_confirm: None,
            scanning: false,
            busy: false,
            activity: "connecting",
            connected: false,
            measuring: false,
            reconnect: false,
            cpu_label: "x86-64 (test fixture)".into(),
            webview_label: "test webview".into(),
            status: String::new(),
            microphones: Vec::new(),
            mic_selected: 0,
            test_volume: 100,
            tone_gain: Arc::new(AtomicU32::new(1.0_f32.to_bits())),
            test_mode: Arc::new(AtomicU32::new(0)),
            session_routes: Vec::new(),
            transition: None,
            stop: Arc::new(AtomicBool::new(false)),
            volume_ui: 50,
            start_notice: String::new(),
            scan_seen: HashMap::new(),
            measured: false,
            connected_at: None,
            buffer_ms: 2000,
            theme: "system".into(),
            last_result: None,
            measuring_since: None,
            saved_json: String::new(),
            dirty_since: None,
            save_blocked: false,
            pushed: String::new(),
        }
    }

    fn add_test_route(app: &mut App, address: &str, selected: bool) {
        let mut route = RouteUi::new();
        route.selected = selected;
        app.speakers.push(Speaker {
            name: "loopback-only regression target".into(),
            address: address.into(),
            ..Default::default()
        });
        app.routes.insert(address.into(), route);
    }

    fn finish_test_start(app: &mut App) {
        // Port zero on loopback cannot be an AirPlay receiver, so no real
        // speaker or capture device is used by these startup regressions.
        app.stop.store(true, Ordering::Release);
        loop {
            match app.receiver.recv_timeout(Duration::from_secs(3)) {
                Ok(Event::WorkerDone(_)) => break,
                Ok(_) => {}
                Err(error) => panic!("startup worker did not stop: {error}"),
            }
        }
        app.busy = false;
    }

    #[test]
    fn bridge_starts_selected_speakers_without_a_pairing_target() {
        for count in [1, 2] {
            for host in ["", "invalid", "192.0.2.80:7000"] {
                let mut app = start_fixture();
                app.host = host.into();
                for i in 1..=count {
                    add_test_route(&mut app, &format!("127.0.0.{i}:0"), true);
                }
                app.start(false);
                assert!(app.busy);
                assert_eq!(app.session_routes.len(), count);
                assert_eq!(app.routes.len(), count);
                finish_test_start(&mut app);
            }
        }
    }

    #[test]
    fn manual_test_tone_registers_its_target_without_changing_bridge_selection() {
        let mut app = start_fixture();
        add_test_route(&mut app, "127.0.0.1:0", true);
        app.host = "127.0.0.2:0".into();
        app.start(true);
        assert!(app.busy);
        assert!(app.session_routes.is_empty());
        assert_eq!(app.speakers.len(), 2);
        assert!(app.routes["127.0.0.1:0"].selected);
        assert!(!app.routes["127.0.0.2:0"].selected);
        finish_test_start(&mut app);
    }

    #[test]
    fn manual_bridge_reuses_live_volume_and_calibration_on_restart() {
        let mut app = start_fixture();
        app.host = "127.0.0.1:0".into();
        app.start(false);
        assert!(app.busy);
        let control = app.routes[&app.host].control.clone();
        finish_test_start(&mut app);
        let route = app.routes.get_mut(&app.host).unwrap();
        route.selected = false;
        route.volume = 42;
        route.delay = 103.4;
        route.control.volume.store(42, Ordering::Release);
        route.control.delay_us.store(103_400, Ordering::Release);
        for tone in [false, true] {
            app.start(tone);
            assert!(app.busy);
            assert!(Arc::ptr_eq(
                &control.volume,
                &app.routes[&app.host].control.volume
            ));
            assert_eq!(app.routes[&app.host].volume, 42);
            assert_eq!(app.routes[&app.host].delay, 103.4);
            assert_eq!(app.speakers.len(), 1);
            finish_test_start(&mut app);
        }
    }

    #[test]
    fn invalid_start_requests_stay_idle_with_a_visible_error() {
        let mut app = start_fixture();
        for tone in [false, true] {
            app.start(tone);
            assert!(!app.busy);
            assert!(!app.status.is_empty());
            assert!(app.session_routes.is_empty());
            assert!(app.routes.is_empty());
        }
        add_test_route(&mut app, "127.0.0.1:0", true);
        app.devices.clear();
        app.start(false);
        assert!(!app.busy);
        assert!(app.status.contains("CABLE Output"));
        assert!(app.session_routes.is_empty());
    }

    #[test]
    fn test_gain_is_equal_on_every_route_and_linear() {
        assert_eq!(super::test_gain(100), 1.0);
        assert_eq!(super::test_gain(50), 0.5);
        assert_eq!(super::test_gain(0), 0.0);
        assert_eq!(super::test_gain(150), 1.0);
        assert_eq!(super::delay_us(0.46), 460);
        assert_eq!(super::delay_us(-3.0), 0);
        assert_eq!(super::delay_us(2500.0), 2_000_000);
    }
    #[test]
    fn stereo_pair_members_must_be_selected_together() {
        let mut app = start_fixture();
        add_test_route(&mut app, "192.0.2.1:7000", true);
        add_test_route(&mut app, "192.0.2.2:7000", false);
        for speaker in &mut app.speakers {
            speaker.pair = Some("B71C0F3E".into());
        }
        let one = vec!["192.0.2.1:7000".to_string()];
        assert!(stereo_pair_notice(&app.speakers, &app.routes, &one).contains("两台都勾选"));
        let both = vec!["192.0.2.1:7000".to_string(), "192.0.2.2:7000".to_string()];
        assert!(stereo_pair_notice(&app.speakers, &app.routes, &both).is_empty());
        app.routes.get_mut("192.0.2.2:7000").unwrap().volume = 50;
        assert!(stereo_pair_notice(&app.speakers, &app.routes, &both).contains("独立音量不同"));
        app.speakers[1].pair = None;
        assert!(stereo_pair_notice(&app.speakers, &app.routes, &both).contains("两台都勾选"));
    }
    #[test]
    fn a_speaker_at_a_new_address_keeps_its_route() {
        let mut app = start_fixture();
        add_test_route(&mut app, "192.0.2.1:7000", true);
        app.speakers[0].id = Some("D2:A5:E0:1A:E3:84".into());
        app.routes.get_mut("192.0.2.1:7000").unwrap().delay = 12.5;
        app.host = "192.0.2.1:7000".into();
        // Another row already sits at the new address; it moves to the old one.
        add_test_route(&mut app, "192.0.2.9:7000", false);
        app.on_found(
            Speaker {
                name: "卧室 (2)".into(),
                address: "192.0.2.9:7000".into(),
                id: Some("D2:A5:E0:1A:E3:84".into()),
                pair: None,
                password: false,
            },
            vec!["192.0.2.9:7000".into()],
        );
        assert_eq!(app.routes["192.0.2.9:7000"].delay, 12.5);
        assert!(app.routes["192.0.2.9:7000"].selected);
        assert!(!app.routes["192.0.2.1:7000"].selected);
        assert_eq!(app.speakers[0].address, "192.0.2.9:7000");
        assert_eq!(app.speakers[0].name, "卧室 (2)");
        assert_eq!(app.speakers[1].address, "192.0.2.1:7000");
        assert_eq!(app.host, "192.0.2.9:7000");
        // A second IPv4 address of the same device in the same scan is ignored.
        app.on_found(
            Speaker {
                name: "卧室 (2)".into(),
                address: "192.0.2.10:7000".into(),
                id: Some("D2:A5:E0:1A:E3:84".into()),
                pair: None,
                password: false,
            },
            vec!["192.0.2.10:7000".into()],
        );
        assert_eq!(app.speakers.len(), 2);
        // Never while a session holds the rows.
        app.scan_seen.clear();
        app.busy = true;
        app.on_found(
            Speaker {
                name: "卧室 (2)".into(),
                address: "192.0.2.11:7000".into(),
                id: Some("D2:A5:E0:1A:E3:84".into()),
                pair: None,
                password: false,
            },
            vec!["192.0.2.11:7000".into()],
        );
        assert_eq!(app.speakers[0].address, "192.0.2.9:7000");
        assert!(app.status.contains("停止播放后重新扫描"));
    }
    #[test]
    fn several_ipv4_addresses_keep_the_saved_row() {
        let (a, b, c, d) = (
            "192.0.2.21:7000",
            "192.0.2.22:7000",
            "192.0.2.23:7000",
            "192.0.2.24:7000",
        );
        let x = || Speaker {
            name: "客厅".into(),
            id: Some("AA:00:00:00:00:21".into()),
            ..Default::default()
        };
        let list = |v: &[&str]| v.iter().map(|a| a.to_string()).collect::<Vec<_>>();
        // The saved address is still announced: no migration in either order.
        let mut app = start_fixture();
        add_test_route(&mut app, a, true);
        app.speakers[0].id = x().id;
        app.on_found(x(), list(&[b, a]));
        assert_eq!(app.speakers.len(), 1);
        assert_eq!(app.speakers[0].address, a);
        assert!(app.status.is_empty());
        app.scan_seen.clear();
        app.on_found(x(), list(&[a, b]));
        assert_eq!(app.speakers[0].address, a);
        assert!(app.status.is_empty());
        // A genuine address change still migrates.
        app.scan_seen.clear();
        app.on_found(x(), list(&[c, d]));
        assert_eq!(app.speakers[0].address, c);
        assert!(app.routes[c].selected);
        // A manual row on any announced address adopts the deviceid.
        let mut app = start_fixture();
        add_test_route(&mut app, a, false);
        app.on_found(x(), list(&[a, b]));
        assert_eq!(app.speakers.len(), 1);
        assert_eq!(app.speakers[0].address, a);
        assert_eq!(app.speakers[0].id, x().id);
        // Another device's row is not relabelled while a free address is announced.
        let mut app = start_fixture();
        add_test_route(&mut app, a, false);
        app.speakers[0].id = Some("BB:00:00:00:00:21".into());
        app.routes.get_mut(a).unwrap().delay = 3.0;
        app.on_found(x(), list(&[a, b]));
        assert_eq!(app.speakers.len(), 2);
        assert_eq!(app.speakers[0].id.as_deref(), Some("BB:00:00:00:00:21"));
        assert_eq!(app.routes[a].delay, 3.0);
        assert_eq!(app.speakers[1].address, b);
        assert_eq!(app.speakers[1].id, x().id);
    }
    #[test]
    fn an_empty_leftover_row_is_merged_and_a_calibrated_one_kept() {
        let (a, b) = ("192.0.2.31:7000", "192.0.2.32:7000");
        let x = || Speaker {
            name: "书房".into(),
            id: Some("AA:00:00:00:00:31".into()),
            ..Default::default()
        };
        let both = vec![a.to_string(), b.to_string()];
        let setup = || {
            let mut app = start_fixture();
            add_test_route(&mut app, a, true);
            add_test_route(&mut app, b, false);
            app.speakers[1].id = x().id;
            app.host = a.into();
            app
        };
        let mut app = setup();
        app.on_found(x(), both.clone());
        assert_eq!(app.speakers.len(), 1);
        assert_eq!(app.speakers[0].address, b);
        assert!(!app.routes.contains_key(a));
        assert!(app.routes[b].selected);
        assert_eq!(app.host, b);
        // A row with a calibration, or one in use, is kept and reported.
        let mut app = setup();
        app.routes.get_mut(a).unwrap().delay = 5.0;
        app.on_found(x(), both.clone());
        assert_eq!(app.speakers.len(), 2);
        assert!(app.status.contains("只勾选一行"));
        // During a session the rows stay and the session status is kept.
        let mut app = setup();
        app.busy = true;
        app.status = "已连接。".into();
        app.on_found(x(), both);
        assert_eq!(app.speakers.len(), 2);
        assert_eq!(app.status, "已连接。");
    }
    #[test]
    fn an_outside_volume_change_warns_during_a_session_only() {
        let _guard = crate::event_pump::TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut app = start_fixture();
        add_test_route(&mut app, "192.0.2.41:7000", true);
        app.speakers[0].name = "卧室".into();
        app.status = "已连接。".into();
        crate::event_pump::report_volume_change("192.0.2.41:7000");
        app.tick();
        assert_eq!(app.status, "已连接。");
        app.busy = true;
        crate::event_pump::report_volume_change("192.0.2.41:7000");
        app.tick();
        assert!(app.status.starts_with("「卧室」的音量在外部被修改"));
        assert!(app.status.contains("建议重新校准"));
        // The app's own level is not changed.
        assert_eq!(app.routes["192.0.2.41:7000"].volume, ROUTE_VOLUME);
    }
    #[test]
    fn manual_test_volume_respects_both_live_sliders() {
        for (master, test, expected) in [
            (100, 100, 1.0),
            (50, 100, 0.5),
            (100, 25, 0.25),
            (50, 25, 0.125),
            (0, 100, 0.0),
            (100, 0, 0.0),
        ] {
            assert!((super::manual_test_gain(master, test) - expected).abs() < 0.00001);
        }
    }
    #[test]
    fn edits_are_saved_without_waiting_for_exit() {
        let mut app = start_fixture();
        add_test_route(&mut app, "192.0.2.1:7000", true);
        app.saved_json = app.settings_json();
        app.autosave();
        assert!(app.dirty_since.is_none());
        app.routes.get_mut("192.0.2.1:7000").unwrap().trim = -1.5;
        app.autosave();
        assert!(app.dirty_since.is_some());
        assert!(app.settings_json().contains("-1.5"));
        app.buffer_ms = 800;
        assert!(app.settings_json().contains("\"buffer_ms\":800"));
    }
    #[test]
    fn calibration_waits_for_receivers_to_settle() {
        let mut app = start_fixture();
        app.connected = true;
        app.test_mode.store(1, Ordering::Release);
        app.connected_at = Some(Instant::now());
        app.calibrate();
        assert!(app.status.contains("同步还在稳定"));
        assert!(!app.measuring);
    }
    #[test]
    fn calibration_progress_follows_the_settle_and_measure_phases() {
        let mut app = start_fixture();
        assert!(app.progress().is_none());
        app.connected = true;
        app.test_mode.store(1, Ordering::Release);
        app.connected_at = Some(Instant::now());
        let (fraction, label) = app.progress().unwrap();
        assert!(fraction < 0.05 && label.contains("同步稳定中"), "{label}");
        app.connected_at = Some(Instant::now() - SETTLE_AFTER_CONNECT);
        assert!(app.progress().is_none());
        app.transition = Some((Instant::now() + Duration::from_millis(2500), true));
        let (fraction, label) = app.progress().unwrap();
        assert!(
            (fraction - 0.5).abs() < 0.05 && label.contains("剩 3 秒"),
            "{label}"
        );
        app.transition = None;
        app.measuring = true;
        app.measuring_since = Some(Instant::now() - Duration::from_secs(60));
        assert!(app.progress().unwrap().0 < 1.0);
    }
    #[test]
    fn calibration_rejects_a_muted_master_level() {
        let mut app = start_fixture();
        app.connected = true;
        app.test_mode.store(1, Ordering::Release);
        app.volume_ui = 0;
        app.calibrate();
        assert!(app.status.contains("总音量为 0%"));
    }
    #[test]
    fn sliders_publish_to_pcm_controls_even_with_staged_calibration() {
        let a = RouteUi::new();
        let mut b = RouteUi::new();
        a.control.volume.store(30, Ordering::Relaxed);
        b.control.volume.store(50, Ordering::Relaxed);
        b.volume = 42; // staged playback value must not change the live test level
        let routes = HashMap::from([("left".into(), a), ("right".into(), b)]);
        let session = vec!["left".into(), "right".into()];
        let tone = AtomicU32::new(1.0_f32.to_bits());
        for test in [100, 50, 0, 25] {
            sync_gains(&routes, &session, 50, test, true, &tone);
            let read = |value: &AtomicU32| f32::from_bits(value.load(Ordering::Relaxed));
            assert_eq!(read(&tone), manual_test_gain(50, test));
            assert_eq!(read(&routes["left"].control.test_gain), test as f32 / 100.0);
            assert_eq!(read(&routes["left"].control.master_gain), 0.5);
            assert_eq!(
                read(&routes["right"].control.test_gain),
                test as f32 / 100.0
            );
            assert_eq!(routes["right"].control.volume.load(Ordering::Relaxed), 50);
            assert_eq!(routes["right"].volume, 42);
        }
        sync_gains(&routes, &session, 25, 50, true, &tone);
        let read = |value: &AtomicU32| f32::from_bits(value.load(Ordering::Relaxed));
        assert_eq!(read(&tone), manual_test_gain(25, 50));
        assert_eq!(read(&routes["left"].control.master_gain), 0.25);
        assert_eq!(read(&routes["left"].control.test_gain), 0.5);
        assert_eq!(read(&routes["right"].control.test_gain), 0.5);
    }

    fn pair_fixture() -> App {
        let mut app = start_fixture();
        for i in 1..=3 {
            add_test_route(&mut app, &format!("192.0.2.{i}:7000"), false);
        }
        app
    }
    const A: &str = "192.0.2.1:7000";
    const B: &str = "192.0.2.2:7000";
    const C: &str = "192.0.2.3:7000";
    fn channel(app: &App, address: &str) -> u32 {
        app.routes[address].control.channel.load(Ordering::Acquire)
    }

    #[test]
    fn a_stereo_pair_is_one_left_and_one_right_speaker_that_play_together() {
        let mut app = pair_fixture();
        app.routes.get_mut(B).unwrap().selected = true;
        app.make_pair(A, B);
        assert_eq!((app.routes[A].mode, app.routes[B].mode), (1, 2));
        assert_eq!((channel(&app, A), channel(&app, B)), (1, 2));
        assert_eq!(app.routes[A].partner.as_deref(), Some(B));
        assert_eq!(app.routes[B].partner.as_deref(), Some(A));
        // Either member ticked before pairing: the pair plays.
        assert!(app.routes[A].selected && app.routes[B].selected);
        app.set_selected(B, false);
        assert!(!app.routes[A].selected && !app.routes[B].selected);
        app.swap_pair(A);
        assert_eq!((app.routes[A].mode, app.routes[B].mode), (2, 1));
        assert_eq!((channel(&app, A), channel(&app, B)), (2, 1));
        // Re-pairing one member with a third speaker frees its old partner.
        app.make_pair(C, A);
        assert_eq!(app.routes[B].partner, None);
        assert_eq!(app.routes[B].mode, 0);
        assert_eq!((app.routes[C].mode, app.routes[A].mode), (1, 2));
        app.unpair(C);
        assert!(
            app.routes
                .values()
                .all(|r| r.partner.is_none() && r.mode == 0)
        );
        app.make_pair(A, A);
        assert!(app.routes[A].partner.is_none());
    }

    #[test]
    fn choosing_a_channel_keeps_or_ends_the_pair() {
        let mut app = pair_fixture();
        app.make_pair(A, B);
        app.set_route_mode(A, 2);
        assert_eq!((app.routes[A].mode, app.routes[B].mode), (2, 1));
        assert_eq!(app.routes[A].partner.as_deref(), Some(B));
        app.set_route_mode(B, 3);
        assert_eq!((app.routes[A].mode, app.routes[B].mode), (0, 3));
        assert!(app.routes[A].partner.is_none() && app.routes[B].partner.is_none());
        app.set_route_mode(C, 9);
        assert_eq!(app.routes[C].mode, 0);
    }

    #[test]
    fn saved_pairs_are_validated_and_older_left_right_settings_become_one() {
        let mut app = pair_fixture();
        app.routes.get_mut(A).unwrap().mode = 1;
        app.routes.get_mut(B).unwrap().mode = 2;
        app.repair_pairs(true);
        assert_eq!(app.routes[A].partner.as_deref(), Some(B));
        assert_eq!(app.routes[B].partner.as_deref(), Some(A));
        // A one-sided link is dropped, and no pair is guessed when two left
        // speakers make the choice ambiguous.
        app.routes.get_mut(B).unwrap().partner = None;
        app.routes.get_mut(C).unwrap().mode = 1;
        app.repair_pairs(true);
        assert!(app.routes.values().all(|r| r.partner.is_none()));
        app.make_pair(A, B);
        assert!(
            app.settings_json()
                .contains(&format!("\"partner\":\"{B}\""))
        );
        // Files written with pairs keep a deliberate unpaired left and right.
        let mut saved = app.settings_snapshot();
        assert!(saved.pairs);
        for route in saved.routes.values_mut() {
            route.partner.clear();
        }
        saved.routes.get_mut(C).unwrap().mode = 0;
        let mut loaded = start_fixture();
        loaded.apply_settings(&saved);
        assert!(loaded.routes.values().all(|r| r.partner.is_none()));
        saved.pairs = false;
        let mut migrated = start_fixture();
        migrated.apply_settings(&saved);
        assert_eq!(migrated.routes[A].partner.as_deref(), Some(B));
    }

    #[test]
    fn an_absent_saved_microphone_or_input_is_not_overwritten() {
        let mut app = start_fixture();
        app.microphones = vec!["Internal".into()];
        app.mic_name = "USB Mic".into();
        app.input_name = "CABLE Output (2)".into();
        let saved = app.settings_snapshot();
        assert_eq!(saved.microphone, "USB Mic");
        assert_eq!(saved.input, "CABLE Output (2)");
        app.command(r#"{"cmd":"setMic","index":0}"#);
        app.command(r#"{"cmd":"setDevice","index":0}"#);
        let saved = app.settings_snapshot();
        assert_eq!(saved.microphone, "Internal");
        assert_eq!(saved.input, "test-capture-must-not-open");
        let list = ["A".to_string(), "B".to_string()];
        assert_eq!(reselect(&list, "B", Some("A".into())), 1);
        assert_eq!(reselect(&list, "gone", Some("B".into())), 1);
        assert_eq!(reselect(&list, "gone", Some("gone".into())), 0);
    }

    #[test]
    fn a_failing_save_is_shown_once_and_retried_later() {
        let mut app = start_fixture();
        app.status = "已连接。".into();
        for _ in 0..3 {
            app.note_save_failure("拒绝访问");
        }
        assert_eq!(app.status.matches("设置保存失败").count(), 1);
        assert!(app.dirty_since.unwrap() > Instant::now());
    }

    #[test]
    fn an_unreadable_settings_file_blocks_saving_only_when_kept_in_place() {
        let mut app = start_fixture();
        app.settings_load_failed("x", false);
        assert!(!app.save_blocked && app.status.contains("settings.json.bad"));
        app.save_with(|_| Ok(()));
        assert_eq!(app.saved_json, app.settings_json());
        app.settings_load_failed("x", true);
        assert!(app.save_blocked && app.status.contains("本次不会保存设置"));
        app.save_with(|_| panic!("a blocked save must not write"));
    }

    #[test]
    fn a_saved_home_pair_warns_before_any_scan() {
        let mut saved = crate::settings::Settings::default();
        for address in [A, B] {
            saved.routes.insert(
                address.into(),
                crate::settings::SavedRoute {
                    home_pair: "B71C0F3E".into(),
                    ..Default::default()
                },
            );
        }
        let mut app = start_fixture();
        app.apply_settings(&saved);
        let one = vec![A.to_string()];
        assert!(stereo_pair_notice(&app.speakers, &app.routes, &one).contains("两台都勾选"));
        assert_eq!(app.settings_snapshot().routes[B].home_pair, "B71C0F3E");
    }

    #[test]
    fn partners_follow_a_speaker_to_its_new_address() {
        let mut app = pair_fixture();
        app.make_pair(A, B);
        let moved = "192.0.2.9:7000";
        app.host = B.into();
        app.repair_confirm = Some(B.into());
        app.move_route(B, moved);
        assert_eq!(app.routes[A].partner.as_deref(), Some(moved));
        assert_eq!(app.routes[moved].partner.as_deref(), Some(A));
        // A confirmation for the old address does not carry over.
        assert_eq!(app.host, moved);
        assert_eq!(app.repair_confirm, None);
    }

    #[test]
    fn page_commands_are_checked_at_the_boundary() {
        let mut app = pair_fixture();
        app.command(&format!(
            r#"{{"cmd":"route","address":"{A}","delay":5000,"trim":4,"volume":300,"mode":7}}"#
        ));
        let route = &app.routes[A];
        assert_eq!(
            (route.delay, route.trim, route.volume, route.mode),
            (2000.0, 0.0, 100, 0)
        );
        app.command(&format!(
            r#"{{"cmd":"makePair","left":"{A}","right":"{C}"}}"#
        ));
        assert_eq!(app.routes[C].partner.as_deref(), Some(A));
        app.command(r#"{"cmd":"route","address":"192.0.2.99:7000","selected":true}"#);
        assert_eq!(app.routes.len(), 3);
        app.command(r#"{"cmd":"setTheme","theme":"neon"}"#);
        assert_eq!(app.theme, "system");
        app.command(r#"{"cmd":"setTheme","theme":"dark"}"#);
        assert_eq!(app.theme, "dark");
        app.command(r#"{"cmd":"setBuffer","value":1234}"#);
        assert_eq!(app.buffer_ms, 1250);
        app.command(r#"{"cmd":"submitPin","pin":"12a4"}"#);
        assert!(app.status.contains("四位数字"));
        app.command("not json");
        // Nothing may change while a measurement owns the routes.
        app.measuring = true;
        app.command(&format!(r#"{{"cmd":"unpair","address":"{A}"}}"#));
        assert_eq!(app.routes[A].partner.as_deref(), Some(C));
    }

    #[test]
    fn the_page_snapshot_lists_pairs_and_the_calibration_pair() {
        let mut app = pair_fixture();
        app.make_pair(A, B);
        app.set_selected(A, true);
        let state: serde_json::Value = serde_json::from_str(&app.state_json()).unwrap();
        assert_eq!(state["calPair"]["left"], A);
        assert_eq!(state["calPair"]["right"], B);
        assert_eq!(state["checks"]["pair"], true);
        assert_eq!(state["speakers"][0]["partner"], B);
        assert_eq!(state["speakers"][0]["level"], "−25.5 dB");
        assert!(app.take_state().is_some());
        assert!(app.take_state().is_none());
        app.command(r#"{"cmd":"ready"}"#);
        assert!(app.take_state().is_some());
    }

    #[test]
    fn every_page_file_is_served_from_the_binary() {
        let html = String::from_utf8_lossy(asset("/index.html").unwrap().0).into_owned();
        let css = String::from_utf8_lossy(asset("/app.css").unwrap().0).into_owned();
        for reference in html
            .split(['"', '\''])
            .chain(css.split(['"', '(', ')']))
            .filter(|s| s.ends_with(".js") || s.ends_with(".css") || s.ends_with(".woff2"))
        {
            assert!(asset(&format!("/{reference}")).is_some(), "{reference}");
        }
        assert!(asset("/mock.js").is_none());
        assert_eq!(asset_response("/nope").status(), 404);
    }

    #[test]
    fn password_protected_speakers_are_detected_from_txt() {
        assert!(txt_requires_password(Some("true"), None));
        assert!(txt_requires_password(Some("TRUE"), None));
        assert!(txt_requires_password(None, Some("0x80")));
        assert!(txt_requires_password(None, Some(" 0X3C4C84 ")));
        assert!(!txt_requires_password(None, Some("0x44")));
        assert!(!txt_requires_password(None, Some("zz")));
        assert!(!txt_requires_password(Some("false"), Some("0x4")));
        assert!(!txt_requires_password(None, None));
    }

    #[test]
    fn auth_failures_of_password_speakers_get_the_hint() {
        let speakers = vec![Speaker {
            address: "192.0.2.5:7000".into(),
            password: true,
            ..Default::default()
        }];
        let at = |a: &str| vec![a.to_owned()];
        let fail = "连接或播放失败：音响 192.0.2.5:7000 验证失败，请检查配对或访问设置。";
        assert!(password_hint(fail, &speakers, &at("192.0.2.5:7000")));
        // The test tone names the target the way it was typed.
        assert!(password_hint(
            "连接或播放失败：音响认证：x",
            &speakers,
            &at("192.0.2.5")
        ));
        assert!(!password_hint(fail, &speakers, &at("192.0.2.6:7000")));
        assert!(!password_hint("已停止。", &speakers, &at("192.0.2.5:7000")));
        assert!(!password_hint(fail, &speakers, &at("")));
        // In a group only the speaker named in the failure counts.
        let both = vec!["192.0.2.5:7000".to_owned(), "192.0.2.55:7000".to_owned()];
        let other = "连接或播放失败：音响 192.0.2.55:7000 验证失败，请检查配对或访问设置。";
        assert!(!password_hint(other, &speakers, &both));
        assert!(password_hint(fail, &speakers, &both));
        // tick() drains the shared volume-change list.
        let _guard = crate::event_pump::TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut app = start_fixture();
        app.speakers = speakers;
        app.host = "192.0.2.5".into();
        let _ = app.events.send(Event::WorkerDone(
            "连接或播放失败：音响认证：refused".into(),
        ));
        app.tick();
        assert!(app.status.contains("连接密码"));
    }

    #[test]
    fn repairing_needs_a_confirmation_for_the_same_host() {
        assert!(!needs_repair_confirm(None, "h", false, false));
        assert!(!needs_repair_confirm(None, "h", true, false));
        assert!(needs_repair_confirm(None, "h", false, true));
        assert!(needs_repair_confirm(None, "h", true, true));
        assert!(needs_repair_confirm(Some("h"), "h", false, true));
        assert!(needs_repair_confirm(Some("other"), "h", true, true));
        assert!(!needs_repair_confirm(Some("h"), "h", true, true));
    }

    #[test]
    fn pairing_failures_say_why_and_keep_the_old_credential() {
        let timeout: Box<dyn std::error::Error> = Box::new(mpsc::RecvTimeoutError::Timeout);
        assert_eq!(
            pair_failure_text(timeout.as_ref(), false),
            "90 秒内未提交 PIN，已取消配对。"
        );
        let stopped: Box<dyn std::error::Error> = Box::new(mpsc::RecvTimeoutError::Disconnected);
        assert_eq!(
            pair_failure_text(stopped.as_ref(), true),
            "已取消配对。旧凭据未更改。"
        );
        let other: Box<dyn std::error::Error> = "M4 refused".into();
        let text = pair_failure_text(other.as_ref(), true);
        assert!(text.starts_with("配对失败或超时") && text.ends_with("旧凭据未更改。"));
        assert!(!text.contains("M4"));
    }

    #[test]
    fn repair_confirmation_is_cleared_and_shown_in_the_snapshot() {
        for body in [
            r#"{"cmd":"pairDevice"}"#,
            r#"{"cmd":"pairDevice","replace":true}"#,
            r#"{"cmd":"cancelPair"}"#,
            r#"{"cmd":"importLegacyCredentials"}"#,
        ] {
            assert!(serde_json::from_str::<Command>(body).is_ok(), "{body}");
        }
        assert!(matches!(
            serde_json::from_str::<Command>(r#"{"cmd":"pairDevice","replace":true}"#),
            Ok(Command::PairDevice { replace: true })
        ));
        let mut app = pair_fixture();
        app.host = A.into();
        app.repair_confirm = Some(A.into());
        let state: serde_json::Value = serde_json::from_str(&app.state_json()).unwrap();
        assert_eq!(state["repairConfirm"], true);
        app.command(&format!(r#"{{"cmd":"setHost","host":"{A}"}}"#));
        assert!(app.repair_confirm.is_some());
        app.command(&format!(r#"{{"cmd":"setTarget","address":"{B}"}}"#));
        assert!(app.repair_confirm.is_none());
        app.repair_confirm = Some(B.into());
        app.command(r#"{"cmd":"cancelPair"}"#);
        assert!(app.repair_confirm.is_none());
        assert!(app.status.contains("旧凭据未更改"));
        app.repair_confirm = Some(B.into());
        app.command(r#"{"cmd":"stop"}"#);
        assert!(app.repair_confirm.is_none());
    }

    #[test]
    fn legacy_import_needs_scanned_deviceids() {
        // No speaker has a deviceid, so the Python vault is never opened.
        let mut app = pair_fixture();
        app.command(r#"{"cmd":"importLegacyCredentials"}"#);
        assert!(app.status.contains("请先扫描音响"));
    }

    #[test]
    fn scans_carry_the_password_flag_into_the_snapshot() {
        let mut app = start_fixture();
        let found = |password| Speaker {
            name: "Kitchen".into(),
            address: "192.0.2.7:7000".into(),
            id: Some("AA:BB:CC:DD:EE:07".into()),
            password,
            ..Default::default()
        };
        app.on_found(found(false), vec!["192.0.2.7:7000".into()]);
        app.on_found(found(true), vec!["192.0.2.7:7000".into()]);
        let state: serde_json::Value = serde_json::from_str(&app.state_json()).unwrap();
        assert_eq!(state["speakers"][0]["needsPassword"], true);
        assert_eq!(state["repairConfirm"], false);
    }

    #[test]
    fn only_the_embedded_page_is_allowed() {
        assert!(allowed_url("http://duetto.localhost/index.html"));
        assert!(allowed_url("http://duetto.localhost/"));
        for url in [
            "file:///C:/Users/me/Desktop/a.html",
            "https://duetto.localhost/index.html",
            "http://duetto.localhost.evil.com/",
            "http://duetto.localhost@evil.com/",
            "http://evil.com/http://duetto.localhost/",
            "about:blank",
        ] {
            assert!(!allowed_url(url), "{url}");
        }
    }

    #[test]
    fn a_second_instance_lock_is_a_sharing_violation() {
        let dir = std::env::temp_dir().join(format!("airbridge-lock-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("instance.lock");
        let first = instance_lock(&path).unwrap();
        assert_eq!(instance_lock(&path).unwrap_err().raw_os_error(), Some(32));
        drop(first);
        drop(instance_lock(&path).unwrap());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn shutdown_waits_for_the_worker_but_not_longer_than_three_seconds() {
        // A bridge session on loopback port zero stops at once.
        let mut app = start_fixture();
        add_test_route(&mut app, "127.0.0.1:0", true);
        app.start(false);
        assert!(app.busy);
        let begun = Instant::now();
        app.shutdown();
        assert!(app.stop.load(Ordering::Acquire));
        assert!(begun.elapsed() < Duration::from_secs(3));

        // A pairing worker waiting for its PIN ends when the sender is dropped.
        let mut app = start_fixture();
        let (pin_tx, pin_rx) = mpsc::channel::<String>();
        let tx = app.events.clone();
        thread::spawn(move || {
            let _ = pin_rx.recv_timeout(Duration::from_secs(90));
            let _ = tx.send(Event::WorkerDone("已取消配对。".into()));
        });
        app.busy = true;
        app.pin_sender = Some(pin_tx);
        let begun = Instant::now();
        app.shutdown();
        assert!(app.pin_sender.is_none());
        assert!(begun.elapsed() < Duration::from_secs(3));

        // A worker that never reports is given up on after the deadline.
        let mut app = start_fixture();
        app.busy = true;
        let begun = Instant::now();
        app.shutdown();
        let waited = begun.elapsed();
        assert!(waited >= Duration::from_secs(3) && waited < Duration::from_millis(3500));
    }

    #[test]
    fn run_state_names_the_tone_and_pairing_instead_of_connecting() {
        let mut app = start_fixture();
        app.host = "invalid".into();
        app.pair_device(false);
        let state: serde_json::Value = serde_json::from_str(&app.state_json()).unwrap();
        assert_eq!(state["run"], "idle");

        app.host = "127.0.0.1:0".into();
        app.start(true);
        let state: serde_json::Value = serde_json::from_str(&app.state_json()).unwrap();
        assert_eq!(state["run"], "tone");
        finish_test_start(&mut app);

        add_test_route(&mut app, "127.0.0.2:0", true);
        app.start(false);
        let state: serde_json::Value = serde_json::from_str(&app.state_json()).unwrap();
        assert_eq!(state["run"], "connecting");
        finish_test_start(&mut app);

        app.busy = true;
        app.activity = "pairing";
        let state: serde_json::Value = serde_json::from_str(&app.state_json()).unwrap();
        assert_eq!(state["run"], "pairing");
    }

    #[test]
    fn a_new_session_or_pair_change_drops_the_old_measurement() {
        let mut app = pair_fixture();
        app.make_pair(A, B);
        for change in 0..4 {
            app.last_result = Some((1.0, 1.0));
            match change {
                0 => app.swap_pair(A),
                1 => app.unpair(A),
                2 => app.make_pair(A, C),
                _ => {
                    app.host = "127.0.0.1:0".into();
                    app.start(true);
                    finish_test_start(&mut app);
                }
            }
            assert_eq!(app.last_result, None, "change {change}");
        }
        // A reconnect and an edited delay or trim drop it too.
        app.last_result = Some((1.0, 1.0));
        let _ = app.events.send(Event::Reconnecting("连接中断".into()));
        app.tick();
        assert_eq!(app.last_result, None);
        for edit in [r#""delay":12.5"#, r#""trim":-1"#] {
            app.last_result = Some((1.0, 1.0));
            app.command(&format!(r#"{{"cmd":"route","address":"{A}",{edit}}}"#));
            assert_eq!(app.last_result, None, "{edit}");
        }
        // Rejected starts and no-op changes keep the result on screen.
        app.last_result = Some((1.0, 1.0));
        app.command(&format!(
            r#"{{"cmd":"route","address":"{A}","delay":12.5}}"#
        ));
        app.unpair(B);
        app.host = "invalid".into();
        app.start(true);
        assert!(app.last_result.is_some());
    }

    #[test]
    fn driver_page_export_and_meter_reach_the_page() {
        for body in [
            r#"{"cmd":"openDriverPage"}"#,
            r#"{"cmd":"exportDiagnostics"}"#,
        ] {
            assert!(serde_json::from_str::<Command>(body).is_ok(), "{body}");
        }
        let mut app = pair_fixture();
        let state: serde_json::Value = serde_json::from_str(&app.state_json()).unwrap();
        assert!(state["inputLevel"].is_null());
        assert!(state["droppedPackets"].is_u64());
        app.connected = true;
        let state: serde_json::Value = serde_json::from_str(&app.state_json()).unwrap();
        assert!(
            state["inputLevel"]
                .as_f64()
                .is_some_and(|db| (-60.0..=0.0).contains(&db))
        );

        app.speakers[0].id = Some("AA:BB:CC:DD:EE:FF".into());
        app.speakers[0].pair = Some("TSID-1234".into());
        let report = app.diagnostics_report();
        assert!(report.contains(A) && report.contains("不包含配对凭据"));
        assert!(!report.contains("AA:BB") && !report.contains("TSID-1234"));
        assert!(report.contains("\"homePair\": true"));
    }
}
