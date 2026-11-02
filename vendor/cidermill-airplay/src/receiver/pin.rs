//! The receiver's one current PIN and the limits on guessing it, shared by every
//! [`super::ReceiverConnection`] through [`super::ReceiverConfig::pin_gate`] (HAP R2 §5.6.2).
//!
//! - One [`PIN_DIGITS`]-digit PIN at a time, valid for [`PIN_LIFETIME`]; a wrong guess replaces it.
//! - No valid PIN at M1: one is drawn and shown, `kTLVError_Authentication` answers, nothing is
//!   counted.
//! - Failures, backoff after [`FREE_FAILURES`] and the `MaxTries` lockout after [`MAX_FAILURES`]
//!   are counted per source (the peer's IP address, an IPv6 one by its /64), so one hostile host
//!   locks only itself out. A source is named by [`PinGate::pin_start_from`] and
//!   [`PinGate::begin_setup_from`]; the calls without one share the [`UNKNOWN_SOURCE`] bucket.
//! - One pair-setup is in flight at a time, receiver-wide (the PIN is receiver-wide, so a second
//!   concurrent guess would be a second guess at one PIN). A hold that times out counts as a
//!   failure of the holder's source, so holding the gate walks that source into its lockout.
//! - A receiver-wide net against a distributed guess: [`GLOBAL_MAX_FAILURES`] failures from all
//!   sources within [`GLOBAL_WINDOW`] lock every source for [`LOCKOUT`] (doubling to
//!   [`LOCKOUT_MAX`]) and withdraw the PIN. This also bounds how often a wrong guess can replace
//!   the PIN for everyone: a backed-off or locked source is refused before it can claim the gate,
//!   so it replaces nothing, and the sources that can are bounded by the net.
//!   The net is deliberately cheap to trip: ten failures from each of five hosts (or fifty from
//!   one that rotates addresses) lock everyone for an hour. That is the bounded design, not a
//!   leak: a distributed guess gets 49 tries an hour, and the cost of denying service is five hosts.
//! - At most [`MAX_TRACKED_SOURCES`] sources are remembered; a new one evicts the least recently
//!   seen source that is not locked. An eviction forgets only a source's own count; the
//!   receiver-wide net still holds it.
//! - Unprompted changes reach the host as [`PinNotice`]s via [`PinGate::take_notices`]; a lock of
//!   one source raises none, since the PIN is still valid for everyone else.
//!
//! Transient pair-setup never touches the gate. Every limit is a named constant and ASSUMED.
//! Sans-io: the clock is injected ([`PinGate::with_clock`]), randomness is the caller's RNG.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use rand_core::CryptoRng;

/// Digits in a PIN.
pub const PIN_DIGITS: usize = 6;

/// How long a drawn PIN stays valid, from the draw.
pub const PIN_LIFETIME: Duration = Duration::from_secs(5 * 60);

/// Failed attempts one source is allowed before any backoff.
pub const FREE_FAILURES: u32 = 3;

/// The first backoff, doubled for each further failure.
pub const BACKOFF_BASE: Duration = Duration::from_secs(2);

/// The longest backoff.
pub const BACKOFF_MAX: Duration = Duration::from_secs(5 * 60);

/// Failed attempts after which one source is locked out of PIN pairing.
pub const MAX_FAILURES: u32 = 10;

/// The first lockout; each further one before a successful pairing doubles it.
pub const LOCKOUT: Duration = Duration::from_secs(60 * 60);

/// The longest lockout.
pub const LOCKOUT_MAX: Duration = Duration::from_secs(24 * 60 * 60);

/// Failed attempts from all sources together, within [`GLOBAL_WINDOW`], that lock every source.
pub const GLOBAL_MAX_FAILURES: usize = 50;

/// The span over which [`GLOBAL_MAX_FAILURES`] are counted.
pub const GLOBAL_WINDOW: Duration = Duration::from_secs(60 * 60);

/// The most sources whose failures are remembered at once.
pub const MAX_TRACKED_SOURCES: usize = 256;

/// How long one PIN pair-setup may hold the gate; a hold past this counts as a failed attempt.
pub const SETUP_IN_FLIGHT_TIMEOUT: Duration = Duration::from_secs(5);

/// The shortest interval between two prompts for the same PIN.
pub const PROMPT_MIN_INTERVAL: Duration = Duration::from_secs(5);

/// `kTLVError_Authentication`.
pub const ERROR_AUTHENTICATION: u8 = 0x02;
/// `kTLVError_Backoff`.
pub const ERROR_BACKOFF: u8 = 0x03;
/// `kTLVError_MaxTries`.
pub const ERROR_MAX_TRIES: u8 = 0x05;
/// `kTLVError_Busy`.
pub const ERROR_BUSY: u8 = 0x07;

/// The source of a request whose peer address is not known: every such request shares it.
pub const UNKNOWN_SOURCE: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

/// Where the gate reads the time: any monotonic reading, as a duration from an arbitrary origin.
pub type Clock = Arc<dyn Fn() -> Duration + Send + Sync>;

/// The key a peer address is counted under: an IPv4-mapped IPv6 address as its IPv4 form, any
/// other IPv6 address by its /64 (a host owns the whole prefix, so counting single addresses
/// would give it unlimited sources).
#[must_use]
pub fn source_key(peer: IpAddr) -> IpAddr {
    match peer.to_canonical() {
        IpAddr::V6(v6) => {
            let mut octets = v6.octets();
            octets[8..].fill(0);
            IpAddr::V6(octets.into())
        }
        v4 => v4,
    }
}

/// Why the gate will not run a PIN pairing right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PinRefusal {
    /// Too many recent failures from this source: try again after this long
    /// (`kTLVError_Backoff`).
    Backoff {
        /// How long until the gate opens again.
        retry_after: Duration,
    },
    /// This source (or, past [`GLOBAL_MAX_FAILURES`], every source) is locked
    /// (`kTLVError_MaxTries`).
    MaxTries,
    /// Another PIN pair-setup is in flight (`kTLVError_Busy`).
    Busy,
}

impl PinRefusal {
    /// The HAP `kTLVType_Error` code.
    #[must_use]
    pub fn code(self) -> u8 {
        match self {
            Self::Backoff { .. } => ERROR_BACKOFF,
            Self::MaxTries => ERROR_MAX_TRIES,
            Self::Busy => ERROR_BUSY,
        }
    }

    /// `kTLVType_RetryDelay` in whole seconds, rounded up, for a backoff.
    #[must_use]
    pub fn retry_delay_seconds(self) -> Option<u16> {
        match self {
            Self::Backoff { retry_after } => Some(
                u16::try_from(retry_after.as_millis().div_ceil(1000))
                    .unwrap_or(u16::MAX)
                    .max(1),
            ),
            _ => None,
        }
    }
}

/// What `/pair-pin-start` did.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PinStart {
    /// Show these digits (newly drawn, or the current ones re-shown).
    Show(String),
    /// The current PIN was shown moments ago; nothing new to show.
    AlreadyShown,
    /// Refused.
    Refused(PinRefusal),
}

/// What a PIN pair-setup M1 got from the gate.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PinClaim {
    /// The gate is this setup's: build the SRP verifier from this PIN.
    Claimed(String),
    /// No PIN was valid: one was drawn; show it and answer M1 with `kTLVError_Authentication`.
    /// Nothing is counted.
    Drawn(String),
    /// Refused.
    Refused(PinRefusal),
}

/// What a failed attempt did to the PIN.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PinAfterFailure {
    /// A new PIN replaced the old one: show it. This includes the failure that locked the
    /// attempt's own source, since the PIN stays valid for every other source.
    Replaced(String),
    /// PIN pairing is now locked for every source ([`GLOBAL_MAX_FAILURES`]); nothing is valid,
    /// hide what was shown.
    LockedOut,
    /// Counted, but its PIN was no longer current, so nothing to replace.
    Counted,
    /// Not counted: the attempt no longer held the gate.
    Unchanged,
}

/// A change to the PIN a host should show, that no request of its own caused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PinNotice {
    /// The PIN shown expired: hide it.
    Expired,
    /// PIN pairing locked for every source (a timed-out hold was the failure that reached
    /// [`GLOBAL_MAX_FAILURES`]): hide the PIN.
    Locked {
        /// How long from now the lock lasts.
        for_duration: Duration,
    },
    /// A receiver-wide lock lifted by itself: PIN pairing works again.
    Unlocked,
}

/// One source's record.
#[derive(Debug, Default, Clone)]
struct SourceState {
    /// Failed attempts since the last success or lock.
    failures: u32,
    /// Locks since the last success (each doubles the next).
    lockouts: u32,
    backoff_until: Option<Duration>,
    locked_until: Option<Duration>,
    last_seen: Duration,
}

#[derive(Debug, Clone, Copy)]
struct InFlight {
    owner: u64,
    since: Duration,
    source: IpAddr,
}

#[derive(Debug, Default)]
struct GateState {
    /// The PIN and when it was drawn.
    current: Option<(String, Duration)>,
    /// When a prompt for the current PIN was last raised.
    last_prompt: Option<Duration>,
    sources: HashMap<IpAddr, SourceState>,
    /// When the failures inside [`GLOBAL_WINDOW`] happened, oldest first.
    recent_failures: VecDeque<Duration>,
    /// Receiver-wide locks since the last success (each doubles the next).
    global_lockouts: u32,
    global_locked_until: Option<Duration>,
    /// The connection holding the in-flight pair-setup, since when, from where.
    in_flight: Option<InFlight>,
    notices: VecDeque<PinNotice>,
}

/// The receiver-wide PIN and its limits. See the module docs.
pub struct PinGate {
    state: Mutex<GateState>,
    clock: Clock,
    next_owner: AtomicU64,
    /// How long one pair-setup may hold the gate ([`SETUP_IN_FLIGHT_TIMEOUT`] by default).
    setup_timeout: Duration,
}

impl std::fmt::Debug for PinGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self.lock();
        f.debug_struct("PinGate")
            .field("pin_valid", &state.current.is_some())
            .field("failures", &state.recent_failures.len())
            .field("sources", &state.sources.len())
            .field("locked", &state.global_locked_until.is_some())
            .finish_non_exhaustive()
    }
}

impl Default for PinGate {
    fn default() -> Self {
        Self::new()
    }
}

impl PinGate {
    /// A gate on the process's monotonic clock.
    #[must_use]
    pub fn new() -> Self {
        let origin = Instant::now();
        Self::with_clock(Arc::new(move || origin.elapsed()))
    }

    /// A gate reading `clock` (tests move it by hand).
    #[must_use]
    pub fn with_clock(clock: Clock) -> Self {
        Self {
            state: Mutex::new(GateState::default()),
            clock,
            next_owner: AtomicU64::new(1),
            setup_timeout: SETUP_IN_FLIGHT_TIMEOUT,
        }
    }

    /// How long one PIN pair-setup may hold the gate before it counts as a failed attempt
    /// (default [`SETUP_IN_FLIGHT_TIMEOUT`]). The hold is wall-clock from M1 to M5 and includes
    /// the receiver's own SRP work, so a host on a slow or starved CPU (an unoptimised build
    /// under load, say) sets it above the default; a longer hold lets one stalled sender block
    /// the others for longer, and still counts against the holder's source.
    #[must_use]
    pub fn with_setup_timeout(mut self, timeout: Duration) -> Self {
        self.setup_timeout = timeout;
        self
    }

    /// A fresh owner id for one connection's pair-setup.
    pub fn register(&self) -> u64 {
        self.next_owner.fetch_add(1, Ordering::Relaxed)
    }

    fn lock(&self) -> MutexGuard<'_, GateState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Brings the time-driven state up to date: an expired PIN, a hold past its timeout (a failed
    /// attempt), a lock or backoff that has run out.
    fn advance(&self) -> (MutexGuard<'_, GateState>, Duration) {
        let now = (self.clock)();
        let mut state = self.lock();
        advance(&mut state, now, self.setup_timeout);
        (state, now)
    }

    /// Everything that changed without a request causing it, since the last call (see
    /// [`PinNotice`]). A host polls this on its own clock — about once a second is plenty.
    pub fn take_notices(&self) -> Vec<PinNotice> {
        let (mut state, _) = self.advance();
        state.notices.drain(..).collect()
    }

    /// The PIN a sender must type now, if one is valid (for a host's display and for tests).
    #[must_use]
    pub fn current_pin(&self) -> Option<String> {
        let (state, _) = self.advance();
        state.current.as_ref().map(|(pin, _)| pin.clone())
    }

    /// Failed attempts from all sources within [`GLOBAL_WINDOW`].
    #[must_use]
    pub fn failures(&self) -> u32 {
        let (state, _) = self.advance();
        u32::try_from(state.recent_failures.len()).unwrap_or(u32::MAX)
    }

    /// Failed attempts `source` has made since its last success or lock.
    #[must_use]
    pub fn failures_for(&self, source: IpAddr) -> u32 {
        let (state, _) = self.advance();
        state
            .sources
            .get(&source_key(source))
            .map_or(0, |s| s.failures)
    }

    /// Whether PIN pairing is locked for every source.
    #[must_use]
    pub fn is_locked(&self) -> bool {
        let (state, _) = self.advance();
        state.global_locked_until.is_some()
    }

    /// Whether `source` is locked out of PIN pairing, by its own failures or the receiver-wide
    /// lock.
    #[must_use]
    pub fn is_locked_for(&self, source: IpAddr) -> bool {
        let (state, now) = self.advance();
        matches!(
            refusal(&state, source_key(source), now),
            Err(PinRefusal::MaxTries)
        )
    }

    /// How many sources are remembered (never more than [`MAX_TRACKED_SOURCES`]).
    #[must_use]
    pub fn tracked_sources(&self) -> usize {
        self.lock().sources.len()
    }

    /// `/pair-pin-start` from an unknown source: see [`Self::pin_start_from`].
    pub fn pin_start(&self, fixed: Option<&str>, rng: &mut dyn CryptoRng) -> PinStart {
        self.pin_start_from(UNKNOWN_SOURCE, fixed, rng)
    }

    /// `/pair-pin-start` from `source`: make sure a PIN is valid and say whether to show it.
    pub fn pin_start_from(
        &self,
        source: IpAddr,
        fixed: Option<&str>,
        rng: &mut dyn CryptoRng,
    ) -> PinStart {
        let source = source_key(source);
        let (mut state, now) = self.advance();
        if let Err(refusal) = refusal(&state, source, now) {
            return PinStart::Refused(refusal);
        }
        if let Some((pin, _)) = &state.current {
            let recently = state
                .last_prompt
                .is_some_and(|at| now.saturating_sub(at) < PROMPT_MIN_INTERVAL);
            if recently {
                return PinStart::AlreadyShown;
            }
            let pin = pin.clone();
            state.last_prompt = Some(now);
            return PinStart::Show(pin);
        }
        PinStart::Show(draw_current(&mut state, now, fixed, rng))
    }

    /// Pair-setup M1 from `owner` at an unknown source: see [`Self::begin_setup_from`].
    pub fn begin_setup(
        &self,
        owner: u64,
        fixed: Option<&str>,
        rng: &mut dyn CryptoRng,
    ) -> PinClaim {
        self.begin_setup_from(owner, UNKNOWN_SOURCE, fixed, rng)
    }

    /// Pair-setup M1 from `owner` at `source`: claims the gate for the current PIN, or draws one
    /// and claims nothing ([`PinClaim::Drawn`]).
    pub fn begin_setup_from(
        &self,
        owner: u64,
        source: IpAddr,
        fixed: Option<&str>,
        rng: &mut dyn CryptoRng,
    ) -> PinClaim {
        let source = source_key(source);
        let (mut state, now) = self.advance();
        if let Err(refusal) = refusal(&state, source, now) {
            return PinClaim::Refused(refusal);
        }
        match state.in_flight {
            Some(held) if held.owner != owner => return PinClaim::Refused(PinRefusal::Busy),
            // A repeated M1 never extends the hold.
            Some(_) | None => {}
        }
        let Some((pin, _)) = state.current.clone() else {
            if state.in_flight.is_some_and(|held| held.owner == owner) {
                state.in_flight = None;
            }
            return PinClaim::Drawn(draw_current(&mut state, now, fixed, rng));
        };
        if state.in_flight.is_none() {
            state.in_flight = Some(InFlight {
                owner,
                since: now,
                source,
            });
        }
        PinClaim::Claimed(pin)
    }

    /// Whether `owner` still holds the in-flight pair-setup (it may have timed out).
    #[must_use]
    pub fn holds(&self, owner: u64) -> bool {
        let (state, _) = self.advance();
        state.in_flight.is_some_and(|held| held.owner == owner)
    }

    /// A PIN attempt by `owner` failed: count it against its source and receiver-wide, release the
    /// gate, and replace the PIN if still current, or lock every source. An attempt that no longer
    /// held the gate is not counted.
    pub fn fail(
        &self,
        owner: u64,
        pin: &str,
        fixed: Option<&str>,
        rng: &mut dyn CryptoRng,
    ) -> PinAfterFailure {
        let (mut state, now) = self.advance();
        let Some(held) = state.in_flight.filter(|held| held.owner == owner) else {
            return PinAfterFailure::Unchanged;
        };
        state.in_flight = None;
        if count_failure(&mut state, held.source, now) {
            return PinAfterFailure::LockedOut;
        }
        let still_current = state
            .current
            .as_ref()
            .is_some_and(|(current, _)| current == pin);
        if !still_current {
            return PinAfterFailure::Counted;
        }
        PinAfterFailure::Replaced(draw_current(&mut state, now, fixed, rng))
    }

    /// `owner`'s pairing with `pin` succeeded (M5 verified). Returns `true` and spends the PIN only
    /// if `owner` still holds the gate and `pin` is current; otherwise the pairing must not be
    /// stored.
    pub fn succeed(&self, owner: u64, pin: &str) -> bool {
        let (mut state, _) = self.advance();
        let held = state.in_flight.filter(|held| held.owner == owner);
        let current = state
            .current
            .as_ref()
            .is_some_and(|(current, _)| current == pin);
        let Some(held) = held.filter(|_| current) else {
            return false;
        };
        state.in_flight = None;
        state.current = None;
        state.last_prompt = None;
        state.sources.remove(&held.source);
        state.recent_failures.clear();
        state.global_lockouts = 0;
        true
    }

    /// `owner` went away mid-setup: let the next one in. Not a failure.
    pub fn release(&self, owner: u64) {
        let mut state = self.lock();
        if state.in_flight.is_some_and(|held| held.owner == owner) {
            state.in_flight = None;
        }
    }
}

/// Time-driven changes: ended locks, a timed-out hold (counted), an expired PIN (dropping any
/// hold on it).
fn advance(state: &mut GateState, now: Duration, setup_timeout: Duration) {
    while state
        .recent_failures
        .front()
        .is_some_and(|at| now.saturating_sub(*at) >= GLOBAL_WINDOW)
    {
        state.recent_failures.pop_front();
    }
    if state.global_locked_until.is_some_and(|until| now >= until) {
        state.global_locked_until = None;
        state.recent_failures.clear();
        state.notices.push_back(PinNotice::Unlocked);
    }
    for source in state.sources.values_mut() {
        if source.locked_until.is_some_and(|until| now >= until) {
            source.locked_until = None;
            source.failures = 0;
        }
        if source.backoff_until.is_some_and(|until| now >= until) {
            source.backoff_until = None;
        }
    }
    if let Some(held) = state.in_flight {
        if now.saturating_sub(held.since) >= setup_timeout {
            state.in_flight = None;
            if count_failure(state, held.source, now) {
                let for_duration = state
                    .global_locked_until
                    .map_or(Duration::ZERO, |until| until - now);
                state.notices.push_back(PinNotice::Locked { for_duration });
            }
        }
    }
    if state
        .current
        .as_ref()
        .is_some_and(|(_, drawn)| now.saturating_sub(*drawn) >= PIN_LIFETIME)
    {
        state.current = None;
        state.last_prompt = None;
        state.in_flight = None;
        state.notices.push_back(PinNotice::Expired);
    }
}

/// Receiver-wide lock, then `source`'s lock, then its backoff.
fn refusal(state: &GateState, source: IpAddr, now: Duration) -> Result<(), PinRefusal> {
    if state.global_locked_until.is_some() {
        return Err(PinRefusal::MaxTries);
    }
    let Some(entry) = state.sources.get(&source) else {
        return Ok(());
    };
    if entry.locked_until.is_some() {
        return Err(PinRefusal::MaxTries);
    }
    if let Some(until) = entry.backoff_until {
        return Err(PinRefusal::Backoff {
            retry_after: until.saturating_sub(now),
        });
    }
    Ok(())
}

/// The length of the lock that follows `earlier` locks: [`LOCKOUT`] doubled each time.
fn lock_length(earlier: u32) -> Duration {
    LOCKOUT
        .checked_mul(1u32 << earlier.min(16))
        .unwrap_or(LOCKOUT_MAX)
        .min(LOCKOUT_MAX)
}

/// Makes room for `source`, evicting the least recently seen source that is not locked (or, if
/// all are, the least recently seen).
fn track(state: &mut GateState, source: IpAddr) {
    if state.sources.contains_key(&source) || state.sources.len() < MAX_TRACKED_SOURCES {
        return;
    }
    let victim = state
        .sources
        .iter()
        .min_by_key(|(_, s)| (s.locked_until.is_some(), s.last_seen))
        .map(|(ip, _)| *ip);
    if let Some(victim) = victim {
        state.sources.remove(&victim);
    }
}

/// Counts one failed attempt by `source`: its backoff after [`FREE_FAILURES`], its lock at
/// [`MAX_FAILURES`] (the PIN stays), and the receiver-wide window. Returns whether the
/// receiver-wide lock engaged, which withdraws the PIN.
fn count_failure(state: &mut GateState, source: IpAddr, now: Duration) -> bool {
    track(state, source);
    let entry = state.sources.entry(source).or_default();
    entry.last_seen = now;
    entry.failures = entry.failures.saturating_add(1);
    if entry.failures >= MAX_FAILURES {
        entry.locked_until = Some(now + lock_length(entry.lockouts));
        entry.lockouts = entry.lockouts.saturating_add(1);
        entry.backoff_until = None;
    } else if entry.failures > FREE_FAILURES {
        let doublings = entry.failures - FREE_FAILURES - 1;
        let delay = BACKOFF_BASE
            .checked_mul(1u32.checked_shl(doublings).unwrap_or(u32::MAX))
            .unwrap_or(BACKOFF_MAX)
            .min(BACKOFF_MAX);
        entry.backoff_until = Some(now + delay);
    }
    state.recent_failures.push_back(now);
    if state.recent_failures.len() >= GLOBAL_MAX_FAILURES {
        state.global_locked_until = Some(now + lock_length(state.global_lockouts));
        state.global_lockouts = state.global_lockouts.saturating_add(1);
        state.current = None;
        state.last_prompt = None;
        return true;
    }
    false
}

/// Draws a new current PIN and marks it shown now.
fn draw_current(
    state: &mut GateState,
    now: Duration,
    fixed: Option<&str>,
    rng: &mut dyn CryptoRng,
) -> String {
    let pin = draw(fixed, rng);
    state.current = Some((pin.clone(), now));
    state.last_prompt = Some(now);
    // A pending expiry would hide the new PIN.
    state.notices.retain(|n| *n != PinNotice::Expired);
    pin
}

/// [`PIN_DIGITS`] uniformly random digits (rejection sampling, no modulo bias), or the fixed PIN.
fn draw(fixed: Option<&str>, rng: &mut dyn CryptoRng) -> String {
    if let Some(pin) = fixed {
        return pin.to_owned();
    }
    const SPACE: u32 = 1_000_000;
    // Values at or above the largest multiple of SPACE are redrawn.
    const LIMIT: u32 = (u32::MAX / SPACE) * SPACE;
    loop {
        let value = rng.next_u32();
        if value < LIMIT {
            return format!("{:0width$}", value % SPACE, width = PIN_DIGITS);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn a_drawn_pin_has_six_digits() {
        let mut rng = StdRng::seed_from_u64(1);
        for _ in 0..200 {
            let pin = draw(None, &mut rng);
            assert_eq!(pin.len(), PIN_DIGITS);
            assert!(pin.bytes().all(|b| b.is_ascii_digit()));
        }
    }

    #[test]
    fn the_retry_delay_rounds_up_and_is_never_zero() {
        let refusal = PinRefusal::Backoff {
            retry_after: Duration::from_millis(1),
        };
        assert_eq!(refusal.retry_delay_seconds(), Some(1));
        let refusal = PinRefusal::Backoff {
            retry_after: Duration::from_millis(2001),
        };
        assert_eq!(refusal.retry_delay_seconds(), Some(3));
        assert_eq!(PinRefusal::Busy.retry_delay_seconds(), None);
    }
}

#[cfg(test)]
mod source_tests {
    use super::*;

    fn ip(n: u32) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + n))
    }

    #[test]
    fn eviction_spares_a_locked_source_even_when_it_is_the_oldest() {
        let mut state = GateState::default();
        for n in 0..MAX_TRACKED_SOURCES {
            let n32 = u32::try_from(n).unwrap();
            state.sources.insert(
                ip(n32),
                SourceState {
                    last_seen: Duration::from_secs(u64::from(n32)),
                    locked_until: (n == 0).then_some(Duration::from_secs(3600)),
                    ..SourceState::default()
                },
            );
        }
        track(&mut state, ip(1_000));
        assert_eq!(state.sources.len(), MAX_TRACKED_SOURCES - 1);
        assert!(state.sources.contains_key(&ip(0)), "the locked one stays");
        assert!(
            !state.sources.contains_key(&ip(1)),
            "the oldest unlocked goes"
        );
    }
}
