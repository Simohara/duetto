//! One capture, broadcast to independent speaker sessions. Any failure stops all.
use crate::{
    capture::Capture,
    routing::{RouteControl, Router},
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, Ordering},
        mpsc::{self, SyncSender, TrySendError},
    },
    thread,
    time::{Duration, Instant},
};

#[derive(Debug)]
pub struct GroupError {
    pub message: String,
    pub retryable: bool,
}
impl std::fmt::Display for GroupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}
impl std::error::Error for GroupError {}
fn authentication_failure(mut error: &(dyn std::error::Error + 'static)) -> bool {
    use cidermill_airplay::AirPlayError;
    loop {
        if matches!(
            error.downcast_ref::<AirPlayError>(),
            Some(
                AirPlayError::Credentials(_)
                    | AirPlayError::PairVerifyRefused(_)
                    | AirPlayError::Pairing(_)
            ) | Some(AirPlayError::Status {
                code: 401 | 403 | 470,
                ..
            })
        ) {
            return true;
        }
        match error.source() {
            Some(source) => error = source,
            None => return false,
        }
    }
}
fn fail(message: impl Into<String>, retryable: bool) -> GroupError {
    GroupError {
        message: message.into(),
        retryable,
    }
}

/// Meter floor in dBFS, and the value while nothing is captured.
const LEVEL_FLOOR: f32 = -60.0;
// About 20 dB per second at 352-frame packets, so peaks stay readable.
const LEVEL_DECAY_DB: f32 = 0.16;
/// Peak input level of the running session in dBFS, as f32 bits.
static INPUT_LEVEL: AtomicU32 = AtomicU32::new(LEVEL_FLOOR.to_bits());

pub fn input_level() -> f32 {
    f32::from_bits(INPUT_LEVEL.load(Ordering::Relaxed))
}

/// The packet's peak, or the previous level fallen back by one step.
fn peak_level(previous: f32, samples: &[i32]) -> f32 {
    let peak = samples.iter().map(|s| s.unsigned_abs()).max().unwrap_or(0) as f32 / 32768.0;
    (20.0 * peak.log10())
        .max(previous - LEVEL_DECAY_DB)
        .clamp(LEVEL_FLOOR, 0.0)
}

const SEND_QUEUE_PACKETS: usize = 64;
// The capture callback must never wait on network I/O. Allow a short sender
// scheduling/control-request stall here, but stop before accumulating seconds
// of latency. Every route keeps the same packet: never drop just one channel.
const SEND_STALL_TIMEOUT: Duration = Duration::from_millis(250);
const SEND_RETRY_INTERVAL: Duration = Duration::from_millis(2);

#[derive(Debug, PartialEq, Eq)]
enum EnqueueError {
    Cancelled,
    Stalled,
    Disconnected,
}

fn enqueue_packet(
    sender: &SyncSender<Vec<i32>>,
    mut packet: Vec<i32>,
    stop: &AtomicBool,
    deadline: Instant,
) -> Result<(), EnqueueError> {
    loop {
        if stop.load(Ordering::Acquire) {
            return Err(EnqueueError::Cancelled);
        }
        match sender.try_send(packet) {
            Ok(()) => return Ok(()),
            Err(TrySendError::Disconnected(_)) => return Err(EnqueueError::Disconnected),
            Err(TrySendError::Full(pending)) => packet = pending,
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(EnqueueError::Stalled);
        }
        thread::sleep(remaining.min(SEND_RETRY_INTERVAL));
    }
}

pub fn run(
    input: String,
    routes: Vec<(String, RouteControl)>,
    stop: Arc<AtomicBool>,
    test_mode: Arc<AtomicU32>,
    report: impl Fn(String) + Send + 'static,
) -> Result<(), GroupError> {
    if routes.is_empty() || routes.len() > 16 {
        return Err(fail("请选择 1–16 台音响", false));
    }
    let mut handles = Vec::new();
    let mut outputs = Vec::new();
    let (ready_tx, ready_rx) = mpsc::channel();
    let (errors_tx, errors_rx) = mpsc::channel();
    let start_clock = Arc::new(crate::playback_clock::SharedStart::new());
    let primed = Arc::new(AtomicBool::new(false));
    for (host, control) in routes {
        let (tx, rx) = mpsc::sync_channel::<Vec<i32>>(SEND_QUEUE_PACKETS);
        let ready = ready_tx.clone();
        let errors = errors_tx.clone();
        let cancel = stop.clone();
        let vol = control.volume.clone();
        let phase = test_mode.clone();
        let output_host = host.clone();
        let clock = start_clock.clone();
        let source_primed = primed.clone();
        handles.push(thread::spawn(move || {
            let result = crate::send_audio(
                &host,
                None,
                cancel.clone(),
                vol,
                None,
                Some(crate::SharedAudio {
                    receiver: rx,
                    ready,
                    clock,
                    primed: source_primed,
                }),
            );
            if let Err(error) = result {
                let fatal = authentication_failure(error.as_ref());
                let mode = match phase.load(Ordering::Acquire) {
                    1 => "连续测试/延迟测量",
                    2 => "音量测量",
                    _ => "正常播放",
                };
                let msg = if fatal {
                    format!("音响 {host} 验证失败，请检查配对或访问设置。")
                } else {
                    format!("音响 {host} 连接中断（{mode}）：{error}")
                };
                let _ = errors.send(fail(msg, !fatal));
                cancel.store(true, Ordering::Release);
            }
        }));
        outputs.push((output_host, tx, Router::new(control)));
    }
    drop(ready_tx);
    drop(errors_tx);
    let started = Instant::now();
    let mut count = 0;
    while count < outputs.len() && !stop.load(Ordering::Acquire) {
        if started.elapsed() > Duration::from_secs(35) {
            stop.store(true, Ordering::Release);
            break;
        }
        if ready_rx.recv_timeout(Duration::from_millis(100)).is_ok() {
            count += 1;
        }
    }
    let result = if stop.load(Ordering::Acquire) {
        Err(errors_rx
            .try_recv()
            .unwrap_or_else(|_| fail("音响连接已取消或超时", true)))
    } else {
        report(format!(
            "{} 台音响已连接，正在采集 CABLE Output。",
            outputs.len()
        ));
        match Capture::start(&input) {
            Err(error) => Err(fail(format!("无法打开采集设备：{error}"), false)),
            Ok(mut capture) => {
                let frames = cidermill_airplay::audio::StreamFormat::PCM_44100_16_STEREO
                    .frames_per_packet as usize;
                let mut failure = None;
                let mut generator = crate::calibration::Generator::new();
                let mut produced_frames = 0;
                let capture_started = Instant::now();
                let mut drift = crate::capture::DriftControl::new();
                while !stop.load(Ordering::Acquire) {
                    match capture.packet(frames) {
                        Ok(mut samples) => {
                            // The captured input, before any test tone replaces it.
                            INPUT_LEVEL.store(
                                peak_level(input_level(), &samples).to_bits(),
                                Ordering::Relaxed,
                            );
                            let mode = test_mode.load(Ordering::Acquire);
                            generator.apply(&mut samples, mode);
                            // One deadline for the entire broadcast, independent of
                            // speaker count. Full queues retain the original packet.
                            let deadline = Instant::now() + SEND_STALL_TIMEOUT;
                            for (host, tx, router) in &mut outputs {
                                match enqueue_packet(
                                    tx,
                                    router.process(&samples, mode != 0),
                                    &stop,
                                    deadline,
                                ) {
                                    Ok(()) => {}
                                    Err(EnqueueError::Stalled) => {
                                        failure = Some(format!(
                                            "音响 {host} 音频发送持续堵塞（缓冲约 {} ms，等待 {} ms 仍未恢复），已停止所有音响。",
                                            SEND_QUEUE_PACKETS * frames * 1000 / 44100,
                                            SEND_STALL_TIMEOUT.as_millis(),
                                        ));
                                        break;
                                    }
                                    Err(EnqueueError::Disconnected) => {
                                        failure = Some(format!("音响 {host} 发送中断。"));
                                        break;
                                    }
                                    Err(EnqueueError::Cancelled) => break,
                                }
                            }
                            produced_frames += frames;
                            if let Some(ppm) =
                                drift.update(produced_frames as u64, capture_started.elapsed())
                            {
                                capture.set_drift_ppm(ppm);
                            }
                            // Python RouteCapture waits for 10 x 10 ms blocks
                            // before releasing every reader together.
                            if produced_frames >= 4410 {
                                primed.store(true, Ordering::Release);
                            }
                        }
                        Err(error) => failure = Some(format!("采集失败：{error}")),
                    }
                    if failure.is_some() {
                        break;
                    }
                }
                match failure {
                    Some(e) => Err(fail(e, true)),
                    None => Ok(()),
                }
            }
        }
    };
    stop.store(true, Ordering::Release);
    INPUT_LEVEL.store(LEVEL_FLOOR.to_bits(), Ordering::Relaxed);
    drop(outputs);
    for handle in handles {
        let _ = handle.join();
    }
    // Keep the producer's original failure (including the stalled target)
    // when closing a session produces a secondary control-channel error.
    let result = match (result, errors_rx.try_recv()) {
        (Err(primary), Ok(sender)) => Err(fail(
            format!("{}；{}", primary.message, sender.message),
            primary.retryable && sender.retryable,
        )),
        (Ok(()), Ok(sender)) => Err(sender),
        (result, Err(_)) => result,
    };
    if let Err(error) = &result {
        crate::diagnostics::record_error(&error.message);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn authentication_errors_are_not_retried() {
        let bad = cidermill_airplay::AirPlayError::PairVerifyRefused("bad".into());
        assert!(authentication_failure(&bad));
        let bad = cidermill_airplay::AirPlayError::Status {
            path: "setup".into(),
            code: 403,
            reason: None,
        };
        assert!(authentication_failure(&bad));
        assert!(!authentication_failure(&std::io::Error::other(
            "disconnected"
        )));
    }

    #[test]
    fn input_level_follows_peaks_and_falls_back_slowly() {
        assert_eq!(peak_level(LEVEL_FLOOR, &[0, 0]), LEVEL_FLOOR);
        assert_eq!(peak_level(LEVEL_FLOOR, &[-32768, 5]), 0.0);
        let half = peak_level(LEVEL_FLOOR, &[16384, -100]);
        assert!((half + 6.02).abs() < 0.01);
        // Silence after a peak decays one step per packet down to the floor.
        assert_eq!(peak_level(half, &[0, 0]), half - LEVEL_DECAY_DB);
        assert_eq!(peak_level(LEVEL_FLOOR + 0.1, &[]), LEVEL_FLOOR);
    }

    #[test]
    fn temporary_full_queue_keeps_both_routes_in_order_without_drops() {
        let (left_tx, left_rx) = mpsc::sync_channel(SEND_QUEUE_PACKETS);
        let (right_tx, right_rx) = mpsc::sync_channel(SEND_QUEUE_PACKETS);
        let count = 300;
        for sequence in 0..SEND_QUEUE_PACKETS as i32 {
            left_tx.send(vec![sequence]).unwrap();
            right_tx.send(vec![sequence]).unwrap();
        }
        // Reproduce the exact condition that used to stop the whole group.
        assert!(matches!(
            right_tx.try_send(vec![-1]),
            Err(TrySendError::Full(_))
        ));
        let left = thread::spawn(move || left_rx.into_iter().collect::<Vec<_>>());
        let right = thread::spawn(move || {
            thread::sleep(Duration::from_millis(30));
            right_rx.into_iter().collect::<Vec<_>>()
        });
        let stop = AtomicBool::new(false);
        for sequence in SEND_QUEUE_PACKETS as i32..count {
            let deadline = Instant::now() + Duration::from_secs(2);
            enqueue_packet(&left_tx, vec![sequence], &stop, deadline).unwrap();
            enqueue_packet(&right_tx, vec![sequence], &stop, deadline).unwrap();
        }
        drop((left_tx, right_tx));
        let expected: Vec<_> = (0..count).map(|sequence| vec![sequence]).collect();
        assert_eq!(left.join().unwrap(), expected);
        assert_eq!(right.join().unwrap(), expected);
    }

    #[test]
    fn persistent_full_queue_times_out_without_overwriting_audio() {
        let (tx, rx) = mpsc::sync_channel(1);
        tx.send(vec![11]).unwrap();
        let started = Instant::now();
        let wait = Duration::from_millis(20);
        assert_eq!(
            enqueue_packet(&tx, vec![22], &AtomicBool::new(false), started + wait),
            Err(EnqueueError::Stalled)
        );
        assert!(started.elapsed() >= wait);
        assert_eq!(rx.try_recv().unwrap(), vec![11]);
        assert_eq!(rx.try_recv(), Err(mpsc::TryRecvError::Empty));
    }

    #[test]
    fn stop_interrupts_a_full_queue_wait() {
        let (tx, _rx) = mpsc::sync_channel(1);
        tx.send(vec![11]).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let cancel = stop.clone();
        let worker = thread::spawn(move || {
            enqueue_packet(
                &tx,
                vec![22],
                &cancel,
                Instant::now() + Duration::from_secs(5),
            )
        });
        thread::sleep(Duration::from_millis(30));
        stop.store(true, Ordering::Release);
        assert_eq!(worker.join().unwrap(), Err(EnqueueError::Cancelled));
    }

    #[test]
    fn disconnected_sender_is_not_treated_as_a_temporary_stall() {
        let (tx, rx) = mpsc::sync_channel(1);
        drop(rx);
        assert_eq!(
            enqueue_packet(
                &tx,
                vec![22],
                &AtomicBool::new(false),
                Instant::now() + SEND_STALL_TIMEOUT,
            ),
            Err(EnqueueError::Disconnected)
        );
    }
}
