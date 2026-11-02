use cpal::{
    SampleFormat, Stream, StreamConfig,
    traits::{DeviceTrait, HostTrait, StreamTrait},
};
use std::{
    collections::VecDeque,
    error::Error,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{Receiver, SyncSender, sync_channel},
    },
    time::Duration,
};

type Frame = [f32; 2];

/// Bounded SPSC queue; callback never waits for network I/O. An overflow is fatal,
/// as continuing would silently skew multiple independently routed speakers.
pub struct Capture {
    _stream: Stream,
    receiver: Receiver<Vec<Frame>>,
    overflow: Arc<AtomicBool>,
    converter: Resampler,
    pending_packet: Vec<i32>,
}

impl Capture {
    pub fn start(name: &str) -> Result<Self, Box<dyn Error>> {
        Self::open(name, false)
    }
    pub fn microphone(name: &str) -> Result<Self, Box<dyn Error>> {
        Self::open(name, true)
    }
    fn open(name: &str, microphone: bool) -> Result<Self, Box<dyn Error>> {
        if !microphone
            && (!name.to_ascii_uppercase().starts_with("CABLE")
                || !name.to_ascii_uppercase().contains("OUTPUT"))
        {
            return Err(tr!(
                "只允许选择 VB-CABLE 的 CABLE Output 录音设备",
                "Only the VB-CABLE recording device, CABLE Output, can be used",
                "録音デバイスは VB-CABLE の CABLE Output のみ選択できます"
            )
            .into());
        }
        if microphone
            && (name.to_ascii_uppercase().starts_with("CABLE")
                || name.to_ascii_uppercase().contains("LOOPBACK"))
        {
            return Err(tr!(
                "请选择物理麦克风",
                "Choose a physical microphone",
                "物理マイクを選択してください"
            )
            .into());
        }
        let mut matches = cpal::default_host()
            .input_devices()?
            .filter(|d| d.name().ok().as_deref() == Some(name));
        let device = matches.next().ok_or_else(|| {
            tr!(
                "未找到指定 CABLE Output",
                "The selected CABLE Output was not found",
                "指定した CABLE Output が見つかりません"
            )
        })?;
        if matches.next().is_some() {
            return Err(tr!(
                "存在同名录音设备，请在 Windows 中重命名",
                "Several recording devices share this name; rename them in Windows",
                "同じ名前の録音デバイスが複数あります。Windows で名前を変更してください"
            )
            .into());
        }
        let format = device.default_input_config()?;
        if !microphone && format.channels() != 2 {
            return Err(tr!(
                "CABLE Output 必须提供立体声录音格式",
                "CABLE Output must record in stereo",
                "CABLE Output はステレオで録音できる必要があります"
            )
            .into());
        }
        let channels = format.channels() as usize;
        if channels == 0 {
            return Err(tr!(
                "录音设备没有声道",
                "The recording device has no channels",
                "録音デバイスにチャンネルがありません"
            )
            .into());
        }
        let rate = format.sample_rate().0;
        let config: StreamConfig = format.clone().into();
        let (tx, rx) = sync_channel::<Vec<Frame>>(32);
        let failed = Arc::new(AtomicBool::new(false));
        let error_flag = failed.clone();
        let error = move |_err| {
            error_flag.store(true, Ordering::Release);
        };
        let stream = match format.sample_format() {
            SampleFormat::F32 => {
                let flag = failed.clone();
                device.build_input_stream(
                    &config,
                    move |data: &[f32], _| {
                        push(
                            data.chunks_exact(channels)
                                .map(|x| {
                                    if microphone {
                                        [x[0], x[0]]
                                    } else {
                                        [x[0], x[1]]
                                    }
                                })
                                .collect(),
                            &tx,
                            &flag,
                        )
                    },
                    error,
                    None,
                )?
            }
            SampleFormat::I16 => {
                let flag = failed.clone();
                device.build_input_stream(
                    &config,
                    move |data: &[i16], _| {
                        push(
                            data.chunks_exact(channels)
                                .map(|x| {
                                    let a = x[0] as f32 / 32768.;
                                    let b = if microphone { a } else { x[1] as f32 / 32768. };
                                    [a, b]
                                })
                                .collect(),
                            &tx,
                            &flag,
                        )
                    },
                    error,
                    None,
                )?
            }
            SampleFormat::U16 => {
                let flag = failed.clone();
                device.build_input_stream(
                    &config,
                    move |data: &[u16], _| {
                        push(
                            data.chunks_exact(channels)
                                .map(|x| {
                                    let a = (x[0] as f32 - 32768.) / 32768.;
                                    let b = if microphone {
                                        a
                                    } else {
                                        (x[1] as f32 - 32768.) / 32768.
                                    };
                                    [a, b]
                                })
                                .collect(),
                            &tx,
                            &flag,
                        )
                    },
                    error,
                    None,
                )?
            }
            _ => {
                return Err(tr!(
                    "当前 CABLE Output 采样格式暂不支持",
                    "This CABLE Output sample format is not supported yet",
                    "この CABLE Output のサンプル形式にはまだ対応していません"
                )
                .into());
            }
        };
        stream.play()?;
        Ok(Self {
            _stream: stream,
            receiver: rx,
            overflow: failed,
            converter: Resampler::new(rate, 44100),
            pending_packet: Vec::new(),
        })
    }

    /// See [`DriftControl`].
    pub fn set_drift_ppm(&mut self, ppm: f64) {
        self.converter.set_correction_ppm(ppm);
    }

    pub fn packet(&mut self, count: usize) -> Result<Vec<i32>, Box<dyn Error>> {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(packet) = self.poll_packet(count)? {
                return Ok(packet);
            }
            if std::time::Instant::now() >= deadline {
                return Err(tr!(
                    "等待录音数据超时",
                    "Timed out waiting for captured audio",
                    "録音データの待機がタイムアウトしました"
                )
                .into());
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    /// Nonblocking counterpart for the playback loop, which must also service
    /// RTSP replies and sync/retransmission while capture is temporarily idle.
    pub fn poll_packet(&mut self, count: usize) -> Result<Option<Vec<i32>>, Box<dyn Error>> {
        while self.pending_packet.len() < count * 2 {
            if self.overflow.load(Ordering::Acquire) {
                return Err(tr!(
                    "音频采集缓冲溢出或设备断开",
                    "The capture buffer overflowed, or the device was disconnected",
                    "音声キャプチャのバッファがあふれたか、デバイスが切断されました"
                )
                .into());
            }
            if let Some(frame) = self.converter.next() {
                for value in frame {
                    self.pending_packet
                        .push((value.clamp(-1.0, 1.0) * 32767.0).round() as i32);
                }
            } else {
                match self.receiver.try_recv() {
                    Ok(frames) => self.converter.feed(frames),
                    Err(std::sync::mpsc::TryRecvError::Empty) => return Ok(None),
                    Err(error) => return Err(error.into()),
                }
            }
        }
        Ok(Some(std::mem::take(&mut self.pending_packet)))
    }
}

const MAX_DRIFT_PPM: f64 = 2000.0;

/// Locks the produced 44.1 kHz stream to real time. VB-CABLE runs on its own
/// clock (measured +729 ppm here, about 2.6 s an hour); receivers play on the
/// shared real-time timeline, so an unlocked source slowly overfills their
/// buffers. Proportional control on the lead over real time: the lead settles
/// at a constant (e.g. 15 ms for 729 ppm) instead of growing. The largest
/// correction, 2000 ppm, is 3.5 cents of pitch.
pub struct DriftControl {
    baseline: Option<f64>,
    next_update: Duration,
}
impl DriftControl {
    /// Capture start-up and the first queue fill are not drift.
    const SETTLE: Duration = Duration::from_secs(5);
    /// Seconds over which a lead deviation is corrected.
    const TIME_CONSTANT: f64 = 20.0;

    pub fn new() -> Self {
        Self {
            baseline: None,
            next_update: Self::SETTLE,
        }
    }
    /// `produced`: frames delivered since capture start, `elapsed`: real time
    /// since then. Returns a new correction about once a second.
    pub fn update(&mut self, produced: u64, elapsed: Duration) -> Option<f64> {
        if elapsed < self.next_update {
            return None;
        }
        self.next_update = elapsed + Duration::from_secs(1);
        let lead = produced as f64 - elapsed.as_secs_f64() * 44_100.0;
        let baseline = *self.baseline.get_or_insert(lead);
        Some(
            ((lead - baseline) / (44_100.0 * Self::TIME_CONSTANT) * 1e6)
                .clamp(-MAX_DRIFT_PPM, MAX_DRIFT_PPM),
        )
    }
}

fn push(frames: Vec<Frame>, tx: &SyncSender<Vec<Frame>>, flag: &AtomicBool) {
    if tx.try_send(frames).is_err() {
        flag.store(true, Ordering::Release);
    }
}

pub(crate) struct Resampler {
    frames: VecDeque<Frame>,
    position: f64,
    step: f64,
    nominal: f64,
}
impl Resampler {
    pub(crate) fn new(source: u32, target: u32) -> Self {
        let nominal = source as f64 / target as f64;
        Self {
            frames: VecDeque::new(),
            position: 0.,
            step: nominal,
            nominal,
        }
    }
    /// A source clock running `ppm` fast is consumed that much faster, so the
    /// output stays at the target rate in real time.
    pub(crate) fn set_correction_ppm(&mut self, ppm: f64) {
        self.step = self.nominal * (1.0 + ppm.clamp(-MAX_DRIFT_PPM, MAX_DRIFT_PPM) * 1e-6);
    }
    pub(crate) fn feed(&mut self, frames: Vec<Frame>) {
        self.frames.extend(frames);
    }
    pub(crate) fn next(&mut self) -> Option<Frame> {
        let i = self.position.floor() as usize;
        if self.frames.len() <= i + 1 {
            return None;
        }
        let a = self.frames[i];
        let b = self.frames[i + 1];
        let f = (self.position - i as f64) as f32;
        let result = [a[0] + (b[0] - a[0]) * f, a[1] + (b[1] - a[1]) * f];
        self.position += self.step;
        let consumed = (self.position.floor() as usize).min(self.frames.len().saturating_sub(1));
        self.frames.drain(..consumed);
        self.position -= consumed as f64;
        Some(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Ten simulated minutes of a source 729 ppm fast, pulled as fast as it
    /// arrives like the shared producer: the lead over real time must stay bounded.
    fn simulated_lead_ms(control: bool) -> f64 {
        let mut resampler = Resampler::new(48_000, 44_100);
        let mut drift = DriftControl::new();
        let source_rate = 48_000.0 * (1.0 + 729e-6);
        let (mut fed, mut produced) = (0.0f64, 0u64);
        let tick = Duration::from_millis(10);
        let mut lead = 0.0;
        for step in 1..=60_000u32 {
            let elapsed = tick * step;
            let due = source_rate * elapsed.as_secs_f64();
            let count = (due - fed).floor() as usize;
            fed += count as f64;
            resampler.feed(vec![[0.0, 0.0]; count]);
            while resampler.next().is_some() {
                produced += 1;
            }
            if control && let Some(ppm) = drift.update(produced, elapsed) {
                resampler.set_correction_ppm(ppm);
            }
            lead = (produced as f64 - elapsed.as_secs_f64() * 44_100.0) / 44.1;
        }
        lead
    }
    #[test]
    fn drift_control_keeps_a_fast_cable_from_overfilling_receivers() {
        let free = simulated_lead_ms(false);
        let locked = simulated_lead_ms(true);
        // Uncorrected, ten minutes at 729 ppm leave ~437 ms of extra audio.
        assert!((free - 437.4).abs() < 5.0, "{free}");
        assert!(locked.abs() < 30.0, "{locked}");
    }
    #[test]
    fn drift_correction_is_bounded() {
        let mut drift = DriftControl::new();
        assert_eq!(drift.update(0, Duration::from_secs(1)), None);
        assert_eq!(drift.update(220_500, Duration::from_secs(5)), Some(0.0));
        // Ten seconds ahead is far beyond any clock error: clamp, never runaway.
        assert_eq!(
            drift.update(220_500 + 44_100 * 11, Duration::from_secs(6)),
            Some(MAX_DRIFT_PPM)
        );
        assert_eq!(drift.update(0, Duration::from_secs(6)), None);
    }
    #[test]
    fn resampling_is_continuous_across_blocks() {
        let samples: Vec<_> = (0..4801).map(|i| [i as f32 / 4800., 0.]).collect();
        fn convert(chunks: impl Iterator<Item = Vec<Frame>>) -> Vec<Frame> {
            let mut r = Resampler::new(48000, 44100);
            let mut out = Vec::new();
            for chunk in chunks {
                r.feed(chunk);
                while let Some(frame) = r.next() {
                    out.push(frame);
                }
            }
            out
        }
        let whole = convert(std::iter::once(samples.clone()));
        let chunked = convert(samples.chunks(127).map(|x| x.to_vec()));
        assert_eq!(whole, chunked);
        assert!((whole.len() as i32 - 4410).abs() <= 1);
    }
}
