//! AirPlay 2 audio send, sans-io: what an audio session needs after the session `SETUP`.
//!
//! - [`mod@format`], [`stream`]: stream types and formats; the stream `SETUP` body and reply.
//! - [`rtp`], [`alac`]: RTP framing and sealing, timestamps; ALAC cookie and frame encoder.
//! - [`ptp`], [`ptp_serve`]: PTP messages and clock filter; the grandmaster side.
//! - [`control`]: `SETPEERS`, `SETPEERSX`, `SETRATEANCHORTIME`, `TEARDOWN`, `FLUSH`, `/feedback`.
//! - [`script`], [`timeline`]: [`AudioSendState`], [`AudioPacketizer`]; [`SendTimeline`] for
//!   multi-room.
//!
//! Nothing here opens a socket. Buffered (type 103) behaviour follows two open receivers and is
//! assumed. A buffered play anchor is refused by tvOS 26 without sender authentication.

pub mod alac;
pub mod control;
pub mod format;
pub mod ptp;
pub mod ptp_serve;
pub mod rtp;
pub mod script;
pub mod stream;
pub mod timeline;

pub use alac::AlacConfig;
pub use control::{RateAnchor, TimingPeerInfo};
pub use format::{StreamFormat, StreamType};
pub use script::{
    Action, AudioPacketizer, AudioSendConfig, AudioSendState, DataTransport, Step, TimingMode,
};
pub use stream::{StreamSetup, StreamSetupResponse};
pub use timeline::SendTimeline;

use crate::error::{AirPlayError, Result};

fn encode_plist(value: &plist::Value, what: &str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    plist::to_writer_binary(&mut out, value)
        .map_err(|e| AirPlayError::Protocol(format!("could not encode the {what} body: {e}")))?;
    Ok(out)
}
