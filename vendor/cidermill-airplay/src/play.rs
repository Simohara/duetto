//! AirPlay media send: pushing a URL at a receiver and driving playback.
//!
//! The classic AirPlay video/photo API: the receiver fetches and plays the URL itself, unlocked by
//! the `legacy` pairing. Blocked on the wire: a legacy-verified `POST /play` is answered 200 and
//! ignored by `AppleTV14,1`; modern Apple TVs require the AirPlay 2 session ([`super::session`]).
//!
//! ```text
//!   POST /play            Content-Location: <url>, Start-Position: <0..1>
//!   POST /rate?value=0|1  pause / resume
//!   POST /scrub?position=<seconds>
//!   GET  /scrub                       -> duration + position
//!   GET  /playback-info               -> plist: rate, position, duration, readyToPlay
//!   POST /stop
//! ```
//!
//! Sans-io: this module builds bodies and parses replies; sockets are in [`super::client`].

use std::collections::BTreeMap;

use plist::Value;

use crate::error::{AirPlayError, Result};

/// `POST /play` body: a binary plist, not `text/parameters` (rejected with 400 on `AppleTV14,1` /
/// tvOS 26.6). Layout: pyatv 0.18.0 `airplayv1.py::play_url`.
///
/// `start_position` is a fraction of the total duration (0.0-1.0), not seconds; it is clamped
/// into that range, and a NaN is sent as 0.
pub fn play_body(url: &str, start_position: f64, session_id: &str) -> Result<Vec<u8>> {
    let mut dict = plist::Dictionary::new();
    dict.insert("Content-Location".to_owned(), Value::String(url.to_owned()));
    let start_position = if start_position.is_nan() {
        0.0
    } else {
        start_position.clamp(0.0, 1.0)
    };
    dict.insert("Start-Position".to_owned(), Value::Real(start_position));
    dict.insert(
        "X-Apple-Session-ID".to_owned(),
        Value::String(session_id.to_owned()),
    );

    let mut out = Vec::new();
    plist::to_writer_binary(&mut out, &Value::Dictionary(dict))
        .map_err(|e| AirPlayError::Protocol(format!("could not encode /play body: {e}")))?;
    Ok(out)
}

/// Content type of [`play_body`].
pub const PLAY_CONTENT_TYPE: &str = "application/x-apple-binary-plist";

/// `X-Apple-ProtocolVersion` sent with [`play_body`]. Observed in pyatv; assumed required.
pub const PLAY_PROTOCOL_VERSION: &str = "1";

/// `X-Apple-Stream-ID` sent with [`play_body`]. Same provenance as [`PLAY_PROTOCOL_VERSION`].
pub const PLAY_STREAM_ID: &str = "1";

/// High-level playback state derived from a [`PlaybackInfo`].
///
/// A receiver reporting an additional state (e.g. buffering or error) is plausible in
/// future firmware, so this enum is `#[non_exhaustive]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PlaybackState {
    /// The receiver has nothing loaded.
    Idle,
    /// The receiver is buffering (not yet ready to play).
    Loading,
    /// The receiver is actively playing (rate > 0).
    Playing,
    /// The receiver is ready but paused (rate = 0, ready to play).
    Paused,
}

impl core::fmt::Display for PlaybackState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Idle => f.write_str("Idle"),
            Self::Loading => f.write_str("Loading"),
            Self::Playing => f.write_str("Playing"),
            Self::Paused => f.write_str("Paused"),
        }
    }
}

/// What a receiver reports about the item it is playing.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
#[non_exhaustive]
pub struct PlaybackInfo {
    /// Total length in seconds, when the receiver knows it.
    pub duration_seconds: Option<f64>,
    /// Current position in seconds.
    pub position_seconds: Option<f64>,
    /// Playback rate: 0.0 paused, 1.0 playing.
    pub rate: Option<f64>,
    /// Whether the receiver has buffered enough to start.
    pub ready_to_play: bool,
    /// True when the receiver answered with an empty body, which is how it says "nothing loaded".
    pub is_idle: bool,
}

impl PlaybackInfo {
    /// Derives a [`PlaybackState`] from this info.
    ///
    /// Idle when no media is loaded, Loading when not yet ready, Playing when rate > 0,
    /// Paused otherwise.
    #[must_use]
    pub fn state(&self) -> PlaybackState {
        if self.is_idle {
            return PlaybackState::Idle;
        }
        if !self.ready_to_play {
            return PlaybackState::Loading;
        }
        if self.rate.unwrap_or(0.0) > 0.0 {
            return PlaybackState::Playing;
        }
        PlaybackState::Paused
    }

    /// Parses a `/playback-info` reply body (a plist, or empty when idle).
    pub fn parse(body: &[u8]) -> Result<Self> {
        if body.iter().all(u8::is_ascii_whitespace) {
            return Ok(Self {
                is_idle: true,
                ..Self::default()
            });
        }

        let value = crate::safe_plist::parse(body, "playback-info is not a plist")?;
        let dict: BTreeMap<String, Value> = value
            .into_dictionary()
            .ok_or_else(|| AirPlayError::Protocol("playback-info is not a dictionary".to_owned()))?
            .into_iter()
            .collect();

        // A receiver that has nothing loaded answers with an (otherwise valid) plist carrying
        // only `readyToPlay: false`, so "no duration and not ready" is the idle signal.
        let ready_to_play = dict
            .get("readyToPlay")
            .and_then(Value::as_boolean)
            .unwrap_or(false);

        Ok(Self {
            duration_seconds: number(&dict, "duration"),
            position_seconds: number(&dict, "position"),
            rate: number(&dict, "rate"),
            ready_to_play,
            is_idle: !ready_to_play && !dict.contains_key("duration"),
        })
    }
}

/// A number field; NaN and infinities read as absent.
fn number(dict: &BTreeMap<String, Value>, key: &str) -> Option<f64> {
    match dict.get(key)? {
        Value::Real(value) => Some(*value),
        Value::Integer(value) => value.as_signed().map(|v| v as f64),
        _ => None,
    }
    .filter(|value| value.is_finite())
}

/// Parses the `text/parameters` body `GET /scrub` answers with.
///
/// Shape: `duration: 123.4\r\nposition: 5.6\r\n`. Returned as `(duration, position)`; either can
/// be absent on a receiver that has nothing loaded. NaN and infinities read as absent.
#[must_use]
pub fn parse_scrub(body: &[u8]) -> (Option<f64>, Option<f64>) {
    let mut duration = None;
    let mut position = None;
    for line in String::from_utf8_lossy(body).lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let parsed = value
            .trim()
            .parse::<f64>()
            .ok()
            .filter(|value| value.is_finite());
        match name.trim().to_ascii_lowercase().as_str() {
            "duration" => duration = parsed,
            "position" => position = parsed,
            _ => {}
        }
    }
    (duration, position)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_idle_when_is_idle() {
        let info = PlaybackInfo {
            is_idle: true,
            ..Default::default()
        };
        assert_eq!(info.state(), PlaybackState::Idle);
    }

    #[test]
    fn state_loading_when_not_ready() {
        let info = PlaybackInfo {
            is_idle: false,
            ready_to_play: false,
            rate: Some(0.0),
            ..Default::default()
        };
        assert_eq!(info.state(), PlaybackState::Loading);
    }

    #[test]
    fn state_playing_when_rate_positive() {
        let info = PlaybackInfo {
            is_idle: false,
            ready_to_play: true,
            rate: Some(1.0),
            duration_seconds: Some(120.0),
            position_seconds: Some(10.0),
        };
        assert_eq!(info.state(), PlaybackState::Playing);
    }

    #[test]
    fn state_paused_when_ready_and_rate_zero() {
        let info = PlaybackInfo {
            is_idle: false,
            ready_to_play: true,
            rate: Some(0.0),
            duration_seconds: Some(120.0),
            position_seconds: Some(10.0),
        };
        assert_eq!(info.state(), PlaybackState::Paused);
    }

    #[test]
    fn state_paused_when_rate_absent_and_ready() {
        let info = PlaybackInfo {
            is_idle: false,
            ready_to_play: true,
            rate: None,
            duration_seconds: Some(120.0),
            position_seconds: Some(10.0),
        };
        assert_eq!(info.state(), PlaybackState::Paused);
    }

    #[test]
    fn a_nan_start_position_is_sent_as_zero() {
        let body = play_body("http://192.0.2.1/a.mp4", f64::NAN, "id").unwrap();
        let dict = plist::Value::from_reader(std::io::Cursor::new(body))
            .unwrap()
            .into_dictionary()
            .unwrap();
        assert_eq!(
            dict.get("Start-Position").and_then(Value::as_real),
            Some(0.0)
        );
    }

    #[test]
    fn non_finite_numbers_from_a_receiver_read_as_absent() {
        assert_eq!(
            parse_scrub(b"duration: NaN\r\nposition: inf\r\n"),
            (None, None)
        );
        assert_eq!(parse_scrub(b"duration: 12.5\r\n"), (Some(12.5), None));
        let mut dict = plist::Dictionary::new();
        dict.insert("duration".to_owned(), Value::Real(f64::INFINITY));
        dict.insert("position".to_owned(), Value::Real(f64::NAN));
        dict.insert("rate".to_owned(), Value::Real(1.0));
        dict.insert("readyToPlay".to_owned(), Value::Boolean(true));
        let mut body = Vec::new();
        plist::to_writer_binary(&mut body, &Value::Dictionary(dict)).unwrap();
        let info = PlaybackInfo::parse(&body).unwrap();
        assert_eq!(info.duration_seconds, None);
        assert_eq!(info.position_seconds, None);
        assert_eq!(info.rate, Some(1.0));
    }

    #[test]
    fn state_display_round_trips() {
        assert_eq!(PlaybackState::Idle.to_string(), "Idle");
        assert_eq!(PlaybackState::Loading.to_string(), "Loading");
        assert_eq!(PlaybackState::Playing.to_string(), "Playing");
        assert_eq!(PlaybackState::Paused.to_string(), "Paused");
    }
}
