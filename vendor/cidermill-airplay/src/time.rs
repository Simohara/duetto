//! The crate's time domains, one type each:
//!
//! - **NTP** wall-clock instants (sync packets, the timing exchange, mirroring headers, the
//!   multi-room timeline): [`NtpTimestamp`], 32.32 fixed point since 1900, wrapping every 136
//!   years; differences are era-safe within 68 years.
//! - **RTP** media time: [`RtpTimestamp`], a frame count modulo 2^32 compared in serial-number
//!   arithmetic (RFC 1982).
//! - **Monotonic** "now" for pacing and timeouts: a [`Duration`] since an origin the caller picks
//!   and keeps (an `Instant` taken at start, say). Only differences between two readings matter.
//! - **PTP** times: [`crate::audio::ptp::Timestamp`] on the wire and nanoseconds on one named
//!   timeline in arithmetic.
//!
//! Signed offsets and errors stay `f64` seconds: a [`Duration`] cannot be negative.

use std::fmt;
use std::ops::{Add, Sub};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Fixed-point units in one second of an [`NtpTimestamp`].
const UNITS_PER_SECOND: f64 = 4_294_967_296.0;

/// Seconds from the NTP epoch (1900) to the Unix epoch (1970).
const NTP_UNIX_OFFSET: u64 = 2_208_988_800;

/// An NTP timestamp (RFC 5905 §6): whole seconds of its era in the high 32 bits, a binary
/// fraction in the low 32. Eras are 136 years long (era 0 from 1900, era 1 from 2036-02-07), and
/// the value does not say which one it is in.
///
/// Not [`Ord`]: across an era boundary the raw order is wrong. Compare with [`Self::is_after`]
/// and subtract with [`Self::units_since`] / [`Self::secs_f64_since`] /
/// [`Self::checked_duration_since`], which are exact for instants within 68 years of each other.
/// Every shift (`wrapping_add*`, `wrapping_sub`, `+`/`-` a [`Duration`]) wraps across eras.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct NtpTimestamp(u64);

impl NtpTimestamp {
    /// The all-zero wire value: the start of an era (1900-01-01 in era 0, 2036-02-07 in era 1;
    /// [`Self::to_system_time`] reads it as the latter).
    pub const ZERO: Self = Self(0);

    /// 1970-01-01 00:00:00 UTC.
    pub const UNIX_EPOCH: Self = Self(NTP_UNIX_OFFSET << 32);

    /// From the 64-bit wire value.
    #[must_use]
    pub const fn from_bits(bits: u64) -> Self {
        Self(bits)
    }

    /// The 64-bit wire value.
    #[must_use]
    pub const fn to_bits(self) -> u64 {
        self.0
    }

    /// From whole seconds of the era and a fraction in 2^-32 s.
    #[must_use]
    pub const fn from_parts(era_secs: u32, fraction: u32) -> Self {
        Self(((era_secs as u64) << 32) | fraction as u64)
    }

    /// `(era_secs, fraction)`.
    #[must_use]
    pub const fn to_parts(self) -> (u32, u32) {
        (self.era_secs(), self.fraction())
    }

    /// Whole seconds since the start of the era: the high 32 bits.
    #[must_use]
    pub const fn era_secs(self) -> u32 {
        (self.0 >> 32) as u32
    }

    /// The fraction of a second, in 2^-32 s: the low 32 bits.
    #[must_use]
    pub const fn fraction(self) -> u32 {
        self.0 as u32
    }

    /// Seconds since the start of the era as a float, for display. Precision falls to about
    /// 2^-21 s late in an era; never subtract two of these, use [`Self::secs_f64_since`].
    #[must_use]
    pub fn era_secs_f64(self) -> f64 {
        f64::from(self.era_secs()) + f64::from(self.fraction()) / UNITS_PER_SECOND
    }

    /// The wall clock now, to the nanosecond the system clock gives.
    #[must_use]
    pub fn now() -> Self {
        Self::from_system_time(SystemTime::now())
    }

    /// A wall-clock time in its era, to the nearest 2^-32 s.
    #[must_use]
    pub fn from_system_time(time: SystemTime) -> Self {
        match time.duration_since(UNIX_EPOCH) {
            Ok(after) => Self::UNIX_EPOCH.wrapping_add(after),
            Err(before) => Self::UNIX_EPOCH.wrapping_sub(before.duration()),
        }
    }

    /// The wall-clock time, taking the era by RFC 4330 §3's rule: era 0 when the top bit is set
    /// (1968-01-20 to 2036-02-07), era 1 when it is clear (2036-02-07 to 2104-02-26). So
    /// [`Self::ZERO`] reads as 2036-02-07 06:28:16 UTC. `None` if [`SystemTime`] cannot hold
    /// the result on this platform.
    #[must_use]
    pub fn to_system_time(self) -> Option<SystemTime> {
        let era: i128 = if self.era_secs() & 0x8000_0000 != 0 {
            0
        } else {
            1 << 64
        };
        let unix = era + i128::from(self.0) - (i128::from(NTP_UNIX_OFFSET) << 32);
        let span = units_to_duration(unix.unsigned_abs());
        if unix >= 0 {
            UNIX_EPOCH.checked_add(span)
        } else {
            UNIX_EPOCH.checked_sub(span)
        }
    }

    /// `duration` in 2^-32 s, rounded to nearest, modulo 2^64 (as a shift of a timestamp wraps).
    #[must_use]
    pub fn units_from_duration(duration: Duration) -> u64 {
        // as_nanos() < 2^95, so the shifted value fits u128.
        let units = ((duration.as_nanos() << 32) + 500_000_000) / 1_000_000_000;
        // Truncation intended: the timestamp wraps with its era.
        #[allow(clippy::cast_possible_truncation)]
        let units = units as u64;
        units
    }

    /// `self - earlier` in 2^-32 s, with wrapping arithmetic (RFC 5905 §6): exact, and right
    /// across an era boundary for instants within 68 years. Negative if `earlier` is later.
    #[must_use]
    pub const fn units_since(self, earlier: Self) -> i64 {
        // Reinterpreting the wrapped difference as i64 is the point: two's complement is the sign.
        self.0.wrapping_sub(earlier.0) as i64
    }

    /// [`Self::units_since`] in seconds; negative if `earlier` is later.
    #[must_use]
    pub fn secs_f64_since(self, earlier: Self) -> f64 {
        #[allow(clippy::cast_precision_loss)]
        let seconds = self.units_since(earlier) as f64 / UNITS_PER_SECOND;
        seconds
    }

    /// [`Self::units_since`] as a [`Duration`], rounded to the nearest nanosecond; `None` if
    /// `earlier` is later.
    #[must_use]
    pub fn checked_duration_since(self, earlier: Self) -> Option<Duration> {
        let units = u64::try_from(self.units_since(earlier)).ok()?;
        Some(units_to_duration(u128::from(units)))
    }

    /// Whether `self` is after `other`, era-safe within 68 years.
    #[must_use]
    pub const fn is_after(self, other: Self) -> bool {
        self.units_since(other) > 0
    }

    /// Moved by `units` 2^-32 s (either sign).
    #[must_use]
    pub const fn wrapping_add_units(self, units: i64) -> Self {
        Self(self.0.wrapping_add_signed(units))
    }

    /// Moved by `seconds` (either sign) to the nearest 2^-32 s; the inverse of
    /// [`Self::secs_f64_since`]. A non-finite shift moves nothing.
    #[must_use]
    pub fn wrapping_add_secs_f64(self, seconds: f64) -> Self {
        if !seconds.is_finite() {
            return self;
        }
        // Saturating float-to-int: a shift beyond +/-68 years is not a clock reading anyway.
        #[allow(clippy::cast_possible_truncation)]
        let units = (seconds * UNITS_PER_SECOND).round() as i64;
        self.wrapping_add_units(units)
    }

    /// Moved forward by `duration`, to the nearest 2^-32 s.
    #[must_use]
    pub fn wrapping_add(self, duration: Duration) -> Self {
        Self(self.0.wrapping_add(Self::units_from_duration(duration)))
    }

    /// Moved back by `duration`, to the nearest 2^-32 s.
    #[must_use]
    pub fn wrapping_sub(self, duration: Duration) -> Self {
        Self(self.0.wrapping_sub(Self::units_from_duration(duration)))
    }
}

impl Add<Duration> for NtpTimestamp {
    type Output = Self;

    /// [`NtpTimestamp::wrapping_add`].
    fn add(self, duration: Duration) -> Self {
        self.wrapping_add(duration)
    }
}

impl Sub<Duration> for NtpTimestamp {
    type Output = Self;

    /// [`NtpTimestamp::wrapping_sub`].
    fn sub(self, duration: Duration) -> Self {
        self.wrapping_sub(duration)
    }
}

impl From<u64> for NtpTimestamp {
    /// [`NtpTimestamp::from_bits`].
    fn from(bits: u64) -> Self {
        Self(bits)
    }
}

impl From<NtpTimestamp> for u64 {
    /// [`NtpTimestamp::to_bits`].
    fn from(value: NtpTimestamp) -> Self {
        value.0
    }
}

impl fmt::Debug for NtpTimestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "NtpTimestamp({:#010x}.{:08x})",
            self.era_secs(),
            self.fraction()
        )
    }
}

impl fmt::Display for NtpTimestamp {
    /// Era seconds and nanoseconds (truncated), e.g. `3900000000.500000000`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let nanos = (u64::from(self.fraction()) * 1_000_000_000) >> 32;
        write!(f, "{}.{nanos:09}", self.era_secs())
    }
}

/// `units` 2^-32 s as a [`Duration`], rounded to the nanosecond.
fn units_to_duration(units: u128) -> Duration {
    let seconds = u64::try_from(units >> 32).unwrap_or(u64::MAX);
    // At most 10^9, so it fits u32; Duration::new carries a full second over.
    #[allow(clippy::cast_possible_truncation)]
    let nanos = (((units & 0xFFFF_FFFF) * 1_000_000_000 + (1 << 31)) >> 32) as u32;
    Duration::new(seconds, nanos)
}

/// An RTP timestamp: a frame count modulo 2^32.
///
/// Not [`Ord`]: RTP time wraps, so order is serial-number arithmetic (RFC 1982) through
/// [`Self::is_after`] and [`Self::signed_frames_since`], meaningful for timestamps under 2^31
/// frames apart. Adding or subtracting frames (`wrapping_add`, `wrapping_sub`, `+`/`-` a `u32`)
/// wraps at 2^32.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct RtpTimestamp(u32);

impl RtpTimestamp {
    /// From the 32-bit wire value.
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// The 32-bit wire value.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }

    /// `frames` later.
    #[must_use]
    pub const fn wrapping_add(self, frames: u32) -> Self {
        Self(self.0.wrapping_add(frames))
    }

    /// `frames` earlier.
    #[must_use]
    pub const fn wrapping_sub(self, frames: u32) -> Self {
        Self(self.0.wrapping_sub(frames))
    }

    /// Frames forward from `earlier` to `self`, modulo 2^32.
    #[must_use]
    pub const fn frames_since(self, earlier: Self) -> u32 {
        self.0.wrapping_sub(earlier.0)
    }

    /// Frames from `other` to `self` on the nearest turn of the wheel: exact within +/-2^31.
    #[must_use]
    pub const fn signed_frames_since(self, other: Self) -> i32 {
        // Reinterpreting the wrapped difference as i32 is the point: two's complement is the sign.
        self.0.wrapping_sub(other.0) as i32
    }

    /// Whether `self` lies after `other` in RFC 1982 serial-number arithmetic. Equal pairs and
    /// pairs exactly 2^31 apart are after in neither direction.
    #[must_use]
    pub const fn is_after(self, other: Self) -> bool {
        self.signed_frames_since(other) > 0
    }
}

impl Add<u32> for RtpTimestamp {
    type Output = Self;

    /// [`RtpTimestamp::wrapping_add`]: `frames` later.
    fn add(self, frames: u32) -> Self {
        self.wrapping_add(frames)
    }
}

impl Sub<u32> for RtpTimestamp {
    type Output = Self;

    /// [`RtpTimestamp::wrapping_sub`]: `frames` earlier.
    fn sub(self, frames: u32) -> Self {
        self.wrapping_sub(frames)
    }
}

impl From<u32> for RtpTimestamp {
    /// [`RtpTimestamp::new`].
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<RtpTimestamp> for u32 {
    /// [`RtpTimestamp::get`].
    fn from(value: RtpTimestamp) -> Self {
        value.0
    }
}

impl fmt::Debug for RtpTimestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RtpTimestamp({})", self.0)
    }
}

impl fmt::Display for RtpTimestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ntp_timestamp_round_trips_through_its_parts_and_bits() {
        let t = NtpTimestamp::from_parts(0xE659_5B21, 0x4000_0000);
        assert_eq!(t.to_bits(), 0xE659_5B21_4000_0000);
        assert_eq!(t.to_parts(), (0xE659_5B21, 0x4000_0000));
        assert_eq!((t.era_secs(), t.fraction()), (0xE659_5B21, 0x4000_0000));
        assert_eq!(NtpTimestamp::from_bits(t.to_bits()), t);
        assert_eq!(NtpTimestamp::from(u64::from(t)), t);
        assert_eq!(NtpTimestamp::default(), NtpTimestamp::ZERO);
    }

    #[test]
    fn differences_are_exact_where_absolute_floats_are_not() {
        // 63 fraction units (15 ns) apart late in the era: absolute f64 seconds keep about 21
        // fraction bits there, so subtracting two of them loses this entirely.
        let a = NtpTimestamp::from_parts(0xF000_0000, 0x40);
        let b = NtpTimestamp::from_parts(0xF000_0000, 0x01);
        assert_eq!(a.units_since(b), 0x3F);
        assert_eq!(a.secs_f64_since(b), f64::from(0x3Fu32) / UNITS_PER_SECOND);
        assert_eq!(b.secs_f64_since(a), -f64::from(0x3Fu32) / UNITS_PER_SECOND);
        assert_eq!(a.era_secs_f64() - b.era_secs_f64(), 0.0);
    }

    #[test]
    fn a_difference_across_the_2036_era_boundary_is_small_not_minus_136_years() {
        let before = NtpTimestamp::from_parts(u32::MAX, 0x8000_0000);
        let after = NtpTimestamp::from_parts(0, 0x8000_0000);
        assert_eq!(after.secs_f64_since(before), 1.0);
        assert_eq!(before.secs_f64_since(after), -1.0);
        assert!(after.is_after(before));
        assert!(!before.is_after(after));
        assert!(!after.is_after(after));
        assert_eq!(
            after.checked_duration_since(before),
            Some(Duration::from_secs(1))
        );
        assert_eq!(before.checked_duration_since(after), None);
    }

    #[test]
    fn every_shift_wraps_across_the_era_and_inverts_the_difference() {
        let late = NtpTimestamp::from_parts(u32::MAX, 0xC000_0000);
        let moved = late.wrapping_add_secs_f64(0.5);
        assert_eq!(
            moved,
            NtpTimestamp::from_parts(0, 0x4000_0000),
            "into era 1"
        );
        assert_eq!(moved.secs_f64_since(late), 0.5);
        assert_eq!(
            moved.wrapping_add_secs_f64(-0.5),
            late,
            "and back into era 0"
        );
        assert_eq!(late + Duration::from_millis(500), moved);
        assert_eq!(late.wrapping_add(Duration::from_millis(500)), moved);
        assert_eq!(moved - Duration::from_millis(500), late);
        assert_eq!(late.wrapping_add_units(1 << 31), moved);
        let seven = NtpTimestamp::from_parts(7, 0);
        assert_eq!(
            seven.wrapping_add_secs_f64(1.25),
            NtpTimestamp::from_parts(8, 0x4000_0000)
        );
        assert_eq!(seven.wrapping_add_secs_f64(f64::NAN), seven);
        assert_eq!(seven.wrapping_add_secs_f64(f64::INFINITY), seven);
        assert_eq!(
            seven.wrapping_add_units(-1),
            NtpTimestamp::from_parts(6, u32::MAX)
        );
    }

    #[test]
    fn a_duration_is_rounded_to_the_nearest_unit_and_back_to_the_nearest_nanosecond() {
        let origin = NtpTimestamp::from_parts(1_000, 0);
        // One nanosecond is 4.29 units: rounded to 4, which reads back as 0.93 ns, so 1 ns.
        assert_eq!(
            NtpTimestamp::units_from_duration(Duration::from_nanos(1)),
            4
        );
        assert_eq!(
            NtpTimestamp::units_from_duration(Duration::from_millis(250)),
            1 << 30
        );
        let one = origin + Duration::from_nanos(1);
        assert_eq!(one.units_since(origin), 4);
        assert_eq!(
            one.checked_duration_since(origin),
            Some(Duration::from_nanos(1))
        );
        for nanos in [0u64, 999_999_999, 1_000_000_000, 123_456_789_012] {
            let d = Duration::from_nanos(nanos);
            assert_eq!(
                (origin + d).checked_duration_since(origin),
                Some(d),
                "{nanos} ns"
            );
        }
        // The largest fraction reads as a whole second, carried.
        let almost = NtpTimestamp::from_parts(0, u32::MAX);
        assert_eq!(
            almost.checked_duration_since(NtpTimestamp::ZERO),
            Some(Duration::from_secs(1))
        );
    }

    #[test]
    fn system_time_converts_with_the_1900_to_1970_offset_and_rfc_4330_eras() {
        assert_eq!(
            NtpTimestamp::from_system_time(UNIX_EPOCH),
            NtpTimestamp::UNIX_EPOCH
        );
        assert_eq!(NtpTimestamp::UNIX_EPOCH.era_secs(), 0x83AA_7E80);
        // 2024-01-01 00:00:00.5 UTC.
        let time = UNIX_EPOCH + Duration::from_millis(1_704_067_200_500);
        let ntp = NtpTimestamp::from_system_time(time);
        assert_eq!(ntp.to_parts(), (3_913_056_000, 0x8000_0000));
        assert_eq!(ntp.to_system_time(), Some(time));
        // RFC 5905 Figure 4: 2036-02-08 00:00 UTC is era 1, offset 63,104.
        let era_1 = UNIX_EPOCH + Duration::from_secs(2_086_041_600);
        assert_eq!(
            NtpTimestamp::from_system_time(era_1),
            NtpTimestamp::from_parts(63_104, 0)
        );
        assert_eq!(
            NtpTimestamp::from_parts(63_104, 0).to_system_time(),
            Some(era_1)
        );
        // The all-zero value is the start of era 1 by the top-bit rule.
        let era_1_start = UNIX_EPOCH + Duration::from_secs((1 << 32) - NTP_UNIX_OFFSET);
        assert_eq!(NtpTimestamp::ZERO.to_system_time(), Some(era_1_start));
        // Before 1970: era 0, and still read back (1969-12-31 23:59:59 UTC).
        let before = UNIX_EPOCH - Duration::from_secs(1);
        let ntp = NtpTimestamp::from_system_time(before);
        assert_eq!(ntp.to_parts(), (0x83AA_7E7F, 0));
        assert_eq!(ntp.to_system_time(), Some(before));
        assert!(NtpTimestamp::now().era_secs() > 3_900_000_000);
    }

    #[test]
    fn an_ntp_timestamp_prints_in_hex_for_debug_and_seconds_for_display() {
        let t = NtpTimestamp::from_parts(3_900_000_000, 0x8000_0000);
        assert_eq!(format!("{t:?}"), "NtpTimestamp(0xe8754700.80000000)");
        assert_eq!(t.to_string(), "3900000000.500000000");
    }

    #[test]
    fn an_rtp_timestamp_wraps_and_orders_in_serial_number_arithmetic() {
        let last = RtpTimestamp::new(u32::MAX);
        let first = last.wrapping_add(1);
        assert_eq!(first, RtpTimestamp::new(0));
        assert_eq!(last + 1, first);
        assert_eq!(first.wrapping_sub(1), last);
        assert_eq!(first - 1, last);
        assert_eq!(first.frames_since(last), 1);
        assert_eq!(last.frames_since(first), u32::MAX);
        assert_eq!(first.signed_frames_since(last), 1);
        assert_eq!(last.signed_frames_since(first), -1);
        assert!(first.is_after(last));
        assert!(!last.is_after(first));
        assert!(!first.is_after(first));
        let half = first.wrapping_add(1 << 31);
        assert!(
            !half.is_after(first) && !first.is_after(half),
            "2^31 apart: neither"
        );
        assert_eq!(u32::from(RtpTimestamp::from(7)), 7);
        assert_eq!(
            format!("{:?} {}", first, last),
            "RtpTimestamp(0) 4294967295"
        );
    }
}
