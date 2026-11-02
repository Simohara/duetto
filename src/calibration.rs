//! Simultaneous timing and isolated level measurements on one active session.
use crate::capture::Capture;
use rustfft::{FftPlanner, num_complex::Complex};
use std::{
    f32::consts::PI,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    time::Duration,
};
const RATE: usize = 44100;
const PERIOD: usize = RATE * 4;
const LENGTH: usize = RATE * 120 / 1000;
const FIRST_ARRIVAL_WINDOW: usize = RATE * 15 / 1000;

fn reference(mut seed: u32) -> Vec<f32> {
    let mut prev = 0f32;
    (0..LENGTH)
        .map(|i| {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            let noise = (seed as f32 / u32::MAX as f32) * 2.0 - 1.0;
            prev = 0.65 * prev + 0.35 * noise;
            let fade = (i as f32 / 220.0)
                .min((LENGTH - 1 - i) as f32 / 220.0)
                .min(1.0);
            prev * fade * 10000.0
        })
        .collect()
}
pub struct Generator {
    position: usize,
    signals: [Vec<f32>; 2],
}
impl Generator {
    pub fn new() -> Self {
        Self {
            position: 0,
            signals: [reference(1357), reference(2468)],
        }
    }
    pub fn apply(&mut self, audio: &mut [i32], mode: u32) {
        if mode == 0 {
            return;
        }
        for frame in audio.as_chunks_mut::<2>().0 {
            let pos = self.position % PERIOD;
            for (channel, sample) in frame.iter_mut().enumerate() {
                // Soft tones identify each speaker by ear and keep the stream
                // from going digitally silent between bursts in either mode.
                let tone = 500.0
                    * (2.0 * PI * (if channel == 0 { 220.0 } else { 330.0 }) * pos as f32
                        / RATE as f32)
                        .sin();
                let value = if mode == 1 {
                    if pos < LENGTH {
                        self.signals[channel][pos]
                    } else {
                        tone
                    }
                } else {
                    let shifted = (pos + PERIOD - channel * RATE) % PERIOD;
                    if shifted < LENGTH {
                        self.signals[0][shifted]
                    } else {
                        tone
                    }
                };
                *sample = value as i32;
            }
            self.position += 1;
        }
    }
}

fn correlation(signal: &[f32], pattern: &[f32]) -> Vec<f32> {
    let n = (signal.len() + pattern.len() - 1).next_power_of_two();
    let mut planner = FftPlanner::<f32>::new();
    let forward = planner.plan_fft_forward(n);
    let inverse = planner.plan_fft_inverse(n);
    let mut a = vec![Complex::new(0., 0.); n];
    let mut b = a.clone();
    for (dst, &x) in a.iter_mut().zip(signal) {
        dst.re = x;
    }
    for (dst, &x) in b.iter_mut().zip(pattern.iter().rev()) {
        dst.re = x;
    }
    forward.process(&mut a);
    forward.process(&mut b);
    for (x, y) in a.iter_mut().zip(b) {
        *x *= y;
    }
    inverse.process(&mut a);
    a[pattern.len() - 1..signal.len()]
        .iter()
        .map(|x| x.re / n as f32)
        .collect()
}
fn rms(values: &[f32]) -> f32 {
    (values.iter().map(|v| v * v).sum::<f32>() / values.len().max(1) as f32).sqrt()
}
fn peaks(signal: &[f32], ref_: &[f32]) -> Result<Vec<(usize, f32)>, String> {
    if signal.len() < ref_.len() + PERIOD * 2 {
        return Err("麦克风录音不完整".into());
    }
    let corr = correlation(signal, ref_);
    let energy = ref_.iter().map(|v| v * v).sum::<f32>();
    let mut order: Vec<(usize, f32)> = Vec::new();
    // At most 12 strongest separated peaks, without another full FFT.
    let mut work = corr.clone();
    for _ in 0..12 {
        let (pos, &value) = work
            .iter()
            .enumerate()
            .max_by(|a, b| a.1.abs().total_cmp(&b.1.abs()))
            .ok_or("未检测到测试音")?;
        let factor = value / energy;
        if factor.abs() < 0.01 {
            break;
        }
        let norm = rms(&signal[pos..pos + ref_.len()]) * rms(ref_) * ref_.len() as f32;
        if norm > 0.0 && value.abs() / norm >= 0.08 {
            // Localization follows the first arrival (precedence effect); in a
            // reflective room the strongest correlation can be an echo a few
            // ms later. Take the earliest tap within 15 ms reaching half of it.
            let first = (pos.saturating_sub(FIRST_ARRIVAL_WINDOW)..=pos)
                .find(|&i| corr[i].abs() >= 0.5 * value.abs())
                .unwrap_or(pos);
            order.push((first, factor));
        }
        let radius = RATE * 3 / 10;
        for v in
            &mut work[pos.saturating_sub(radius)..(pos + radius).min(signal.len() - ref_.len() + 1)]
        {
            *v = 0.;
        }
    }
    order.sort_by_key(|x| x.0);
    Ok(order)
}
/// Timing and level from one recording of the level-mode signal: the same
/// burst on the left at 0 s and on the right at 1 s of every 4 s period. The
/// bursts never overlap, so a much louder or nearer speaker cannot mask the
/// other one, and no separate timing pass is needed to pair them.
/// Returns `(right minus left arrival in ms, right minus left level in dB)`.
pub fn analyze(signal: &[f32]) -> Result<(f64, f64), String> {
    if signal.iter().any(|x| x.abs() > 32000.) {
        return Err("麦克风削顶，请降低测试音量".into());
    }
    let p = peaks(signal, &reference(1357))?;
    if p.is_empty() {
        return Err("没有检测到测试脉冲：请提高测试音量或总音量，并确认选择了正确的麦克风".into());
    }
    let repeats = |idx: usize| {
        p.iter()
            .any(|&(o, _)| (o as i64 - idx as i64 - PERIOD as i64).abs() < (RATE / 100) as i64)
    };
    // Right follows left by 1 s +/- 700 ms; the next left follows the right
    // by 2.3-3.7 s, so a pair in this window is always (left, right).
    let window = (RATE * 3 / 10) as i64..=(RATE * 17 / 10) as i64;
    let mut pairs = Vec::new();
    for &(left, _) in &p {
        let right = p
            .iter()
            .map(|&(r, _)| r as i64 - left as i64)
            .filter(|gap| window.contains(gap))
            .min_by_key(|gap| (gap - RATE as i64).abs());
        if let Some(gap) = right {
            let right = left + gap as usize;
            if repeats(left) && repeats(right) {
                let l = burst_rms(signal, left);
                let r = burst_rms(signal, right);
                if l < 30. || r < 30. {
                    return Err("麦克风音量信号过弱，请提高测试音量".into());
                }
                pairs.push((
                    (gap - RATE as i64) as f64 * 1000.0 / RATE as f64,
                    20.0 * (r / l).log10() as f64,
                ));
            }
        }
    }
    if pairs.is_empty() {
        let two_sided = p.iter().any(|&(a, _)| {
            p.iter().any(|&(b, _)| {
                let gap = (b as i64 - a as i64).rem_euclid(PERIOD as i64);
                window.contains(&gap) || window.contains(&(PERIOD as i64 - gap))
            })
        });
        return Err(if two_sided {
            format!(
                "两侧测试脉冲没有稳定重复（检测到 {} 个），请保持安静、关闭麦克风降噪后重试",
                p.len()
            )
        } else {
            format!(
                "只检测到一侧的测试脉冲（{} 个），另一侧太弱或没有发声；连续测试时请确认左侧 220 Hz 低音和右侧 330 Hz 高音都能听到",
                p.len()
            )
        });
    }
    let spread = |values: &mut Vec<f64>| {
        values.sort_by(f64::total_cmp);
        (
            values[values.len() / 2],
            values[values.len() - 1] - values[0],
        )
    };
    let (timing, timing_spread) = spread(&mut pairs.iter().map(|x| x.0).collect());
    if timing_spread > 5.0 {
        return Err(format!(
            "延迟测量不一致（相差 {timing_spread:.1} ms），请保持安静、不要移动麦克风后重试"
        ));
    }
    let (level, level_spread) = spread(&mut pairs.iter().map(|x| x.1).collect());
    if level_spread > 3.0 || level.abs() > 18.0 {
        return Err("音量测量不稳定或差异过大".into());
    }
    Ok((timing, level))
}
/// Burst level with the steady tones and room noise of the 150 ms before it
/// removed by power subtraction, so the soft tones do not bias the result.
fn burst_rms(signal: &[f32], start: usize) -> f32 {
    let burst = rms(&signal[start..start + LENGTH]);
    let gap = RATE * 30 / 1000;
    let span = RATE * 150 / 1000;
    let base = if start >= gap + span {
        rms(&signal[start - gap - span..start - gap])
    } else {
        0.0
    };
    (burst * burst - base * base).max(0.0).sqrt()
}
/// Keeps the last failed recording for diagnosis; overwritten on the next failure.
fn save_failed_recording(signal: &[f32]) -> Option<std::path::PathBuf> {
    let path = std::path::PathBuf::from(std::env::var_os("LOCALAPPDATA")?)
        .join("AirBridge-Rust")
        .join("last-failed-measurement.wav");
    let samples: Vec<u8> = signal
        .iter()
        .flat_map(|x| (x.clamp(-32768.0, 32767.0) as i16).to_le_bytes())
        .collect();
    let mut wav = Vec::with_capacity(44 + samples.len());
    for part in [
        &b"RIFF"[..],
        &(36 + samples.len() as u32).to_le_bytes(),
        b"WAVEfmt ",
        &16u32.to_le_bytes(),
        &1u16.to_le_bytes(),
        &1u16.to_le_bytes(),
        &(RATE as u32).to_le_bytes(),
        &(RATE as u32 * 2).to_le_bytes(),
        &2u16.to_le_bytes(),
        &16u16.to_le_bytes(),
        b"data",
        &(samples.len() as u32).to_le_bytes(),
        &samples,
    ] {
        wav.extend_from_slice(part);
    }
    std::fs::create_dir_all(path.parent()?).ok()?;
    std::fs::write(&path, wav).ok()?;
    Some(path)
}
pub fn record(
    mic: &str,
    stop: &AtomicBool,
    mode: &AtomicU32,
    expected: u32,
) -> Result<Vec<f32>, String> {
    let mut capture = Capture::microphone(mic).map_err(|e| format!("无法打开麦克风：{e}"))?;
    let mut result = Vec::with_capacity(RATE * 13);
    while result.len() < RATE * 13 {
        if stop.load(Ordering::Acquire) || mode.load(Ordering::Acquire) != expected {
            return Err("连接或测试已结束，测量已取消".into());
        }
        let count = (RATE * 13 - result.len()).min(2048);
        let block = capture
            .packet(count)
            .map_err(|e| format!("麦克风录音失败：{e}"))?;
        result.extend(block.as_chunks::<2>().0.iter().map(|s| s[0] as f32));
    }
    Ok(result)
}
/// Delays (ms) and PCM level trims (dB) after one measurement:
/// `(left_delay, right_delay, left_trim, right_trim, difference_ms, level_db)`.
pub type Proposal = (f64, f64, f64, f64, f64, f64);

/// `difference`: right arrival minus left, in ms. `sensitivity`: right level
/// minus left, in dB, measured through the same PCM trims and receiver volumes
/// used for playback, so no receiver volume curve is assumed. Only the earlier
/// side is delayed and only the louder side is attenuated.
pub fn propose(
    difference: f64,
    sensitivity: f64,
    left_delay: f64,
    right_delay: f64,
    left_trim: f64,
    right_trim: f64,
) -> Result<Proposal, String> {
    if !difference.is_finite() || !sensitivity.is_finite() {
        return Err("测量结果无效".into());
    }
    // `+ 0.0` turns -0.0 into 0.0 for display.
    let tenth = |value: f64| (value * 10.0).round() / 10.0 + 0.0;
    let dl = left_delay + difference.max(0.0);
    let dr = right_delay + (-difference).max(0.0);
    let common = dl.min(dr);
    let (dl, dr) = (tenth(dl - common), tenth(dr - common));
    if dl > 2000.0 || dr > 2000.0 {
        return Err("所需延迟超出范围".into());
    }
    let (mut tl, mut tr) = (left_trim, right_trim);
    if sensitivity > 0.0 {
        tr -= sensitivity;
    } else {
        tl += sensitivity;
    }
    let top = tl.max(tr);
    let (tl, tr) = (tenth(tl - top), tenth(tr - top));
    if tl.min(tr) < -24.0 {
        return Err("所需电平修正超过 24 dB，请检查音响摆放或先调整独立音量".into());
    }
    Ok((dl, dr, tl, tr, difference, sensitivity))
}
pub fn measure(
    mic: String,
    stop: Arc<AtomicBool>,
    mode: Arc<AtomicU32>,
    left_delay: f64,
    right_delay: f64,
    left_trim: f64,
    right_trim: f64,
) -> Result<Proposal, String> {
    if stop.load(Ordering::Acquire) || mode.load(Ordering::Acquire) != 1 {
        return Err("测试已结束".into());
    }
    mode.store(2, Ordering::Release);
    let result = (|| {
        // Let the send queue and receiver buffers play out the previous signal.
        for _ in 0..40 {
            if stop.load(Ordering::Acquire) || mode.load(Ordering::Acquire) != 2 {
                return Err("测试已取消".into());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let audio = record(&mic, &stop, &mode, 2)?;
        let (difference, sensitivity) =
            analyze(&audio).map_err(|error| match save_failed_recording(&audio) {
                Some(path) => format!("{error}（录音已保存到 {}）", path.display()),
                None => error,
            })?;
        propose(
            difference,
            sensitivity,
            left_delay,
            right_delay,
            left_trim,
            right_trim,
        )
    })();
    if mode.load(Ordering::Acquire) == 2 {
        mode.store(1, Ordering::Release);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Level-mode recording: left burst at `t`, right at `t + 1 s + offset`.
    fn staggered(offset: usize, left: f32, right: f32) -> Vec<f32> {
        let mut audio = vec![0f32; RATE * 13];
        let sig = reference(1357);
        for t in [RATE / 2, RATE / 2 + PERIOD, RATE / 2 + 2 * PERIOD] {
            for (i, &x) in sig.iter().enumerate() {
                audio[t + i] += x * left;
                audio[t + RATE + offset + i] += x * right;
            }
        }
        audio
    }
    #[test]
    fn detects_staggered_timing_and_level() {
        // Right 73 ms later and 6 dB quieter.
        let (ms, db) = analyze(&staggered(3219, 0.5, 0.25)).unwrap();
        assert!((ms - 73.0).abs() < 0.1, "{ms}");
        assert!((db + 6.02).abs() < 0.2, "{db}");
        // Right earlier: negative difference.
        let mut audio = vec![0f32; RATE * 13];
        let sig = reference(1357);
        for t in [RATE / 2, RATE / 2 + PERIOD, RATE / 2 + 2 * PERIOD] {
            for (i, &x) in sig.iter().enumerate() {
                audio[t + i] += x * 0.4;
                audio[t + RATE - 20 + i] += x * 0.4;
            }
        }
        let (ms, db) = analyze(&audio).unwrap();
        assert!((ms + 20.0 * 1000.0 / RATE as f64).abs() < 0.05, "{ms}");
        assert!(db.abs() < 0.1);
    }
    #[test]
    fn a_stronger_echo_does_not_hide_the_direct_sound() {
        // Each burst: direct sound, then a 1.5x stronger reflection 6 ms later
        // on the left only. Timing must use the left direct sound.
        let mut audio = staggered(441, 0.2, 0.4);
        let sig = reference(1357);
        let echo = RATE * 6 / 1000;
        for t in [RATE / 2, RATE / 2 + PERIOD, RATE / 2 + 2 * PERIOD] {
            for (i, &x) in sig.iter().enumerate() {
                audio[t + echo + i] += x * 0.3;
            }
        }
        let (ms, _) = analyze(&audio).unwrap();
        assert!((ms - 10.0).abs() < 0.1, "{ms}");
    }
    #[test]
    fn soft_tones_between_bursts_do_not_bias_the_level() {
        let mut audio = staggered(0, 0.5, 0.25);
        for (i, sample) in audio.iter_mut().enumerate() {
            *sample += 500.0 * (2.0 * PI * 220.0 * i as f32 / RATE as f32).sin();
        }
        let (_, db) = analyze(&audio).unwrap();
        assert!((db + 6.02).abs() < 0.3, "{db}");
    }
    #[test]
    fn level_mode_never_goes_silent_between_bursts() {
        let mut generator = Generator::new();
        let mut audio = vec![0; PERIOD * 2];
        generator.apply(&mut audio, 2);
        let quiet = audio
            .chunks(RATE / 10 * 2)
            .filter(|block| block.iter().all(|&s| s == 0))
            .count();
        assert_eq!(quiet, 0);
    }
    #[test]
    fn a_much_louder_side_does_not_mask_the_other() {
        // 17 dB apart, which failed when both bursts played at once.
        let (_, db) = analyze(&staggered(0, 0.5, 0.5 * 10f32.powf(-17.0 / 20.0))).unwrap();
        assert!((db + 17.0).abs() < 0.2, "{db}");
    }
    #[test]
    fn missing_side_and_silence_are_named() {
        let silent = vec![0f32; RATE * 13];
        assert!(analyze(&silent).unwrap_err().contains("没有检测到测试脉冲"));
        let one_side = staggered(0, 0.5, 0.0);
        assert!(analyze(&one_side).unwrap_err().contains("只检测到一侧"));
        let mut clipped = staggered(0, 0.5, 0.5);
        clipped[RATE] = 32767.;
        assert!(analyze(&clipped).unwrap_err().contains("削顶"));
    }
    #[test]
    fn correction_respects_existing_settings() {
        // Right arrives 73.2 ms early and is 6 dB quieter: delay the right
        // side and attenuate the left one; the right keeps its existing 30 ms.
        let result = propose(-73.2, -6.0, 0.0, 30.0, 0.0, 0.0).unwrap();
        assert_eq!(
            (result.0, result.1, result.2, result.3),
            (0.0, 103.2, -6.0, 0.0)
        );
        // Sub-millisecond: 0.46 ms early on the right is kept to 0.1 ms.
        let result = propose(-0.46, 0.0, 0.0, 0.0, 0.0, 0.0).unwrap();
        assert_eq!((result.0, result.1), (0.0, 0.5));
        // A residual on an existing trim moves the trim, never above 0 dB.
        let result = propose(0.0, 1.0, 0.0, 0.0, -3.0, 0.0).unwrap();
        assert_eq!((result.2, result.3), (-2.0, 0.0));
        let result = propose(0.0, -1.0, 0.0, 0.0, 0.0, -0.5).unwrap();
        assert_eq!((result.2, result.3), (-0.5, 0.0));
        // A balanced result leaves both untouched, with no negative zero.
        let result = propose(0.0, 0.0, 12.0, 0.0, 0.0, -2.0).unwrap();
        assert_eq!(result.0.to_bits(), 12.0f64.to_bits());
        assert_eq!(result.2.to_bits(), 0.0f64.to_bits());
        assert!(propose(0.0, 1.0, 0.0, 0.0, 0.0, -23.5).is_err());
        assert!(propose(2100.0, 0.0, 0.0, 0.0, 0.0, 0.0).is_err());
        assert!(propose(f64::NAN, 0.0, 0.0, 0.0, 0.0, 0.0).is_err());
    }
    #[test]
    fn timing_survives_48000_hz_microphone_resampling() {
        let original = staggered(3219, 0.4, 0.4);
        let microphone: Vec<[f32; 2]> = (0..RATE * 13 * 48000 / 44100)
            .map(|i| {
                let pos = i as f64 * 44100.0 / 48000.0;
                let n = pos.floor() as usize;
                let f = (pos - n as f64) as f32;
                let a = original[n];
                let b = original[(n + 1).min(original.len() - 1)];
                let v = a + (b - a) * f;
                [v, v]
            })
            .collect();
        let mut converter = crate::capture::Resampler::new(48000, 44100);
        converter.feed(microphone);
        let mut recorded = Vec::new();
        while let Some(f) = converter.next() {
            recorded.push(f[0]);
        }
        assert!((analyze(&recorded).unwrap().0 - 73.0).abs() < 0.2);
    }
}
