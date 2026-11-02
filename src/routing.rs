//! Per-speaker channel routing, live delay and bounded broadcast.
use std::{
    collections::VecDeque,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
};

#[derive(Clone)]
pub struct RouteControl {
    pub channel: Arc<AtomicU32>, // 0 stereo, 1 left, 2 right, 3 mono
    /// Microseconds: a 1 ms step moves a phantom centre audibly toward the
    /// nearer speaker (precedence effect), so calibration keeps 0.1 ms.
    pub delay_us: Arc<AtomicU32>,
    pub volume: Arc<AtomicU32>,
    /// Common playback amplitude ratio encoded as f32 bits. Hardware levels
    /// stay fixed so moving the master slider preserves relative dB offsets.
    pub master_gain: Arc<AtomicU32>,
    /// Test-only PCM gain encoded as f32 bits; playback gain remains unchanged.
    pub test_gain: Arc<AtomicU32>,
    /// Calibrated PCM level correction in dB (<= 0) as f32 bits. Unlike the
    /// receiver volume it is exact and cannot be changed by the speaker.
    pub trim_db: Arc<AtomicU32>,
}
impl RouteControl {
    pub fn new() -> Self {
        Self {
            channel: Arc::new(AtomicU32::new(0)),
            delay_us: Arc::new(AtomicU32::new(0)),
            volume: Arc::new(AtomicU32::new(35)),
            master_gain: Arc::new(AtomicU32::new(1.0f32.to_bits())),
            test_gain: Arc::new(AtomicU32::new(1.0f32.to_bits())),
            trim_db: Arc::new(AtomicU32::new(0.0f32.to_bits())),
        }
    }
}

pub struct Router {
    control: RouteControl,
    pending: VecDeque<[i32; 2]>,
}
impl Router {
    pub fn new(control: RouteControl) -> Self {
        Self {
            control,
            pending: VecDeque::new(),
        }
    }
    pub fn process(&mut self, input: &[i32], test_active: bool) -> Vec<i32> {
        assert_eq!(input.len() % 2, 0);
        let target = ((self.control.delay_us.load(Ordering::Relaxed).min(2_000_000) as u64 * 44100
            + 500_000)
            / 1_000_000) as usize;
        while self.pending.len() < target {
            self.pending.push_front([0, 0]);
        }
        while self.pending.len() > target {
            self.pending.pop_front();
        }
        let mode = self.control.channel.load(Ordering::Relaxed);
        let master =
            f32::from_bits(self.control.master_gain.load(Ordering::Relaxed)).clamp(0.0, 1.0);
        let test = if test_active {
            f32::from_bits(self.control.test_gain.load(Ordering::Relaxed)).clamp(0.0, 1.0)
        } else {
            1.0
        };
        let trim = f32::from_bits(self.control.trim_db.load(Ordering::Relaxed));
        let trim = if trim.is_finite() {
            10f32.powf(trim.clamp(-60.0, 0.0) / 20.0)
        } else {
            1.0
        };
        let gain = master * test * trim;
        let mut output = Vec::with_capacity(input.len());
        for s in input.as_chunks::<2>().0 {
            let frame = match mode {
                1 => [s[0], s[0]],
                2 => [s[1], s[1]],
                3 => {
                    let x = (s[0] + s[1]) / 2;
                    [x, x]
                }
                _ => [s[0], s[1]],
            };
            let frame = if gain != 1.0 {
                [
                    (frame[0] as f32 * gain).round() as i32,
                    (frame[1] as f32 * gain).round() as i32,
                ]
            } else {
                frame
            };
            self.pending.push_back(frame);
            output.extend(self.pending.pop_front().unwrap());
        }
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn routing_and_delay_changes_keep_frames_ordered() {
        let c = RouteControl::new();
        c.channel.store(1, Ordering::Relaxed);
        c.delay_us.store(1000, Ordering::Relaxed);
        let mut r = Router::new(c.clone());
        let input: Vec<i32> = (0..100).flat_map(|i| [i, -i]).collect();
        let o = r.process(&input, false);
        assert_eq!(o[..88], [0; 88]);
        assert_eq!(&o[88..94], &[0, 0, 1, 1, 2, 2]);
        c.delay_us.store(0, Ordering::Relaxed);
        c.channel.store(2, Ordering::Relaxed);
        let o = r.process(&[9, -9, 10, -10], false);
        assert_eq!(o, vec![-9, -9, -10, -10]);
    }
    #[test]
    fn sub_millisecond_delay_and_trim_are_applied() {
        let c = RouteControl::new();
        // 0.5 ms is 22.05 frames: rounded to 22, not truncated to a whole millisecond.
        c.delay_us.store(500, Ordering::Relaxed);
        c.trim_db.store((-6.0f32).to_bits(), Ordering::Relaxed);
        let mut r = Router::new(c.clone());
        let input: Vec<i32> = (1..=40).flat_map(|_| [10000, 10000]).collect();
        let o = r.process(&input, false);
        assert_eq!(o[..44], [0; 44]);
        let expected = (10000.0 * 10f32.powf(-6.0 / 20.0)).round() as i32;
        assert_eq!(&o[44..46], &[expected, expected]);
        // Out-of-range or invalid trims never amplify.
        c.trim_db.store(3.0f32.to_bits(), Ordering::Relaxed);
        c.delay_us.store(0, Ordering::Relaxed);
        let o = r.process(&[10000, 10000], false);
        assert_eq!(o, vec![10000, 10000]);
        c.trim_db.store(f32::NAN.to_bits(), Ordering::Relaxed);
        assert_eq!(r.process(&[10000, 10000], false), vec![10000, 10000]);
    }
    #[test]
    fn test_gain_never_changes_normal_playback() {
        let c = RouteControl::new();
        c.channel.store(1, Ordering::Relaxed);
        c.test_gain.store(0.25f32.to_bits(), Ordering::Relaxed);
        let mut r = Router::new(c);
        assert_eq!(r.process(&[1000, 500], true), vec![250, 250]);
        assert_eq!(r.process(&[1000, 500], false), vec![1000, 1000]);
    }
    #[test]
    fn master_ratio_scales_live_without_changing_receiver_db_difference() {
        let left = RouteControl::new();
        let right = RouteControl::new();
        left.volume.store(30, Ordering::Relaxed);
        right.volume.store(50, Ordering::Relaxed);
        let mut left_router = Router::new(left.clone());
        let mut right_router = Router::new(right.clone());
        let receiver_gain = |volume: u32| 10f64.powf((-30.0 + volume as f64 * 0.3) / 20.0);
        // At the receiver, the routes differ by 6 dB. Common PCM attenuation
        // must preserve that difference at every nonzero master setting.
        for gain in [1.0f32, 0.5, 0.25, 0.0, 1.0] {
            left.master_gain.store(gain.to_bits(), Ordering::Relaxed);
            right.master_gain.store(gain.to_bits(), Ordering::Relaxed);
            let l = left_router.process(&[16000, 16000], false)[0];
            let r = right_router.process(&[16000, 16000], false)[0];
            assert_eq!(l, (16000.0 * gain) as i32);
            assert_eq!(r, l);
            if gain > 0.0 {
                let db = 20.0
                    * ((r as f64 * receiver_gain(50)) / (l as f64 * receiver_gain(30))).log10();
                assert!((db - 6.0).abs() < 1e-9);
            }
            assert_eq!(left.volume.load(Ordering::Relaxed), 30);
            assert_eq!(right.volume.load(Ordering::Relaxed), 50);
        }
    }
    #[test]
    fn test_gain_updates_live_and_combines_with_master() {
        let c = RouteControl::new();
        let mut router = Router::new(c.clone());
        c.master_gain.store(1.0f32.to_bits(), Ordering::Relaxed);
        for gain in [1.0f32, 0.5, 0.25, 0.0, 1.0] {
            c.test_gain.store(gain.to_bits(), Ordering::Relaxed);
            assert_eq!(
                router.process(&[8000, -8000], true),
                vec![(8000.0 * gain) as i32, (-8000.0 * gain) as i32]
            );
            assert_eq!(router.process(&[8000, -8000], false), vec![8000, -8000]);
        }
        c.master_gain.store(0.5f32.to_bits(), Ordering::Relaxed);
        assert_eq!(router.process(&[8000, -8000], false), vec![4000, -4000]);
        c.test_gain.store(0.25f32.to_bits(), Ordering::Relaxed);
        assert_eq!(router.process(&[8000, -8000], true), vec![1000, -1000]);
        c.master_gain.store(0.0f32.to_bits(), Ordering::Relaxed);
        assert_eq!(router.process(&[8000, -8000], false), vec![0, 0]);
        assert_eq!(router.process(&[8000, -8000], true), vec![0, 0]);
    }
}
