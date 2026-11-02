//! AirPlay 2 for Rust, sender and receiver, sans-io.
//!
//! Every protocol layer (RTSP codec, HAP pairing, ChaCha20-Poly1305 framing, timing, audio
//! packets, the receiver's answers) is bytes in, bytes out, and opens no socket, so it runs over
//! any transport. [`ControlChannel`], [`session::EventChannel`] and [`timing::TimingServer`] are
//! thin blocking wrappers over `std::net` for the common case.
//!
//! | Feature | Adds |
//! |---|---|
//! | (default) | pairing, the encrypted control channel, URL playback, realtime and buffered audio, timing, metadata, the receiver |
//! | `legacy` | pre-HAP PIN pairing (SHA-1, AES-GCM, AES-CTR) |
//! | `mirror` | screen mirroring: stream setup, packets, H.264 framing, the stream cipher |
//! | `raop-rsa` | AirPlay 1 `et` 1 for a sender: the AirPort Express public key, OAEP, AES-CBC audio |
//!
//! Not included: FairPlay (Apple TVs and HomePods take little beyond realtime audio without it),
//! audio and video encoders (ALAC frames are verbatim), and an async runtime (drive
//! [`SenderConnection`] or [`receiver::ReceiverConnection`] from yours).
//!
//! The receiver's ALAC decoding needs `panic = "unwind"` (the default): the third-party decoder
//! can panic on hostile packets, and [`receiver::PacketDecoder::decode`] catches that and returns
//! an error. Under `panic = "abort"` such a packet ends the process.
//!
//! # Sender
//!
//! ```no_run
//! use cidermill_airplay::pairing::HapCredentials;
//! use cidermill_airplay::{Auth, ControlChannel, OsRng};
//!
//! # fn main() -> cidermill_airplay::Result<()> {
//! let credentials = HapCredentials::parse("...")?; // from a PIN pairing (examples/pair.rs)
//! let mut channel = ControlChannel::builder("192.0.2.10").connect()?;
//! channel.authenticate(Auth::Stored(&credentials), &mut OsRng)?;
//! let _playback = channel.start_url_playback("http://192.0.2.1/movie.mp4", 0.0)?;
//! println!("{:?}", channel.playback_info()?.state());
//! channel.stop_playback()?;
//! channel.teardown()?;
//! # Ok(()) }
//! ```
//!
//! Realtime audio is [`audio::AudioSendState`] plus [`audio::AudioPacketizer`]
//! (`examples/send_audio.rs`). AirPlay 1 audio in the clear, for receivers that
//! list `et` 0, is [`raop`]. Times are typed ([`time`]): [`NtpTimestamp`], [`RtpTimestamp`], and a
//! [`Duration`](std::time::Duration) since an origin the caller picks for a monotonic "now".
//!
//! # Receiver
//!
//! ```no_run
//! use std::io::{Read, Write};
//! use cidermill_airplay::receiver::{PortKind, ReceiverConfig, ReceiverConnection, ReceiverIdentity};
//! use cidermill_airplay::OsRng;
//!
//! # fn main() -> cidermill_airplay::Result<()> {
//! let identity = ReceiverIdentity::generate("Living Room", &mut OsRng);
//! let config = ReceiverConfig::builder(identity, 7000).url_playback(true).build();
//! let (mut socket, peer) = std::net::TcpListener::bind("0.0.0.0:7000")?.accept()?;
//! let mut connection = ReceiverConnection::new(config, socket.local_addr()?.ip(), Box::new(OsRng));
//! connection.set_peer_ip(peer.ip()); // PIN limits count failures per sender
//! // Bind a socket of this kind and return its port (examples/receiver.rs does).
//! let mut ports = |_kind: PortKind| -> cidermill_airplay::Result<u16> { Ok(50_000) };
//! let mut buffer = [0; 4096];
//! let started = std::time::Instant::now(); // the monotonic clock the connection is handed
//! loop {
//!     let read = socket.read(&mut buffer)?;
//!     if read == 0 {
//!         break;
//!     }
//!     socket.write_all(&connection.receive(&buffer[..read], &mut ports, started.elapsed())?)?;
//!     while let Some(event) = connection.poll_event() {
//!         println!("{event:?}"); // a PIN to show, a URL to play, a stream to open
//!     }
//! }
//! # Ok(()) }
//! ```
//!
//! Audio a receiver is sent plays through [`receiver::RealtimeStream`] (or
//! [`receiver::BufferedStream`]), timed by a [`timing::NtpFollower`] of the sender's clock; the
//! host keeps the sockets and the sink, and `examples/receiver.rs` shows the loop.
//!
//! AirPlay is a trademark of Apple Inc. This project is not affiliated with or endorsed by Apple.

#![deny(missing_docs)]

pub mod audio;
pub mod cipher;
pub mod client;
pub mod command;
pub mod datastream;
pub mod dmap;
pub mod error;
pub mod extension;
pub mod features;
pub mod info;
#[cfg(feature = "legacy")]
pub mod legacy;
#[cfg(feature = "mirror")]
pub mod mirror;
mod os_rng;
pub mod pairing;
pub mod play;
pub mod raop;
pub mod receiver;
pub mod rtsp;
pub mod safe_plist;
pub mod sequence;
pub mod session;
pub mod srp6a;
pub mod time;
pub mod timing;
pub mod tlv8;
pub mod util;

pub use client::{Auth, ControlChannel, MediaSession, SenderConnection};
// Foreign types in public signatures, so callers need not match their versions by hand.
pub use ed25519_dalek::{SigningKey, VerifyingKey};
pub use error::{AirPlayError, Result};
pub use features::Features;
pub use info::DeviceInfo;
pub use os_rng::OsRng;
pub use play::PlaybackState;
pub use plist;
pub use rand_core::{self, CryptoRng};
pub use rtsp::{Headers, Protocol, Request, Response};
pub use time::{NtpTimestamp, RtpTimestamp};
pub use tlv8::Tlv8;

/// Identity this crate presents to a receiver when the embedding application supplies none of
/// its own: the `User-Agent` app name ([`client::ControlChannel`]), the pairing identifier
/// ([`pairing::constants::CLIENT_IDENTIFIER`]) and the sender name in a v2 session
/// ([`session::SetupParams::name`], `clientProcName`). This is a protocol library, not an
/// application, so nothing here should be read as a real product's name — override it wherever
/// the type in question exposes a setter or a constructor parameter for it.
pub const DEFAULT_CLIENT_NAME: &str = "cidermill-airplay";

/// HAP pairing methods (`kTLVType_Method`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[repr(u8)]
pub enum Method {
    /// Set up a new pairing, no PIN.
    PairSetup = 0,
    /// Set up a new pairing with a PIN shown on the device.
    PairSetupWithAuth = 1,
    /// Verify an existing pairing and derive session keys.
    PairVerify = 2,
    /// Add a pairing on an already-paired device.
    AddPairing = 3,
    /// Remove a pairing.
    RemovePairing = 4,
    /// List pairings.
    ListPairings = 5,
}

/// Error codes a receiver can return in `kTLVType_Error`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PairingError {
    /// `0x01` — the receiver did not say why.
    Unknown,
    /// `0x02` — the PIN or proof was wrong.
    Authentication,
    /// `0x03` — too many attempts; wait before retrying.
    Backoff,
    /// `0x04` — the receiver is out of pairing slots.
    MaxPeers,
    /// `0x05` — too many failed attempts; the device must be reset.
    MaxTries,
    /// `0x06` — pairing is not available right now.
    Unavailable,
    /// `0x07` — the receiver is busy with another pairing.
    Busy,
    /// Something outside the documented set.
    Other(u8),
}

impl PairingError {
    /// Maps a raw `kTLVType_Error` byte.
    #[must_use]
    pub fn from_code(code: u8) -> Self {
        match code {
            0x01 => Self::Unknown,
            0x02 => Self::Authentication,
            0x03 => Self::Backoff,
            0x04 => Self::MaxPeers,
            0x05 => Self::MaxTries,
            0x06 => Self::Unavailable,
            0x07 => Self::Busy,
            other => Self::Other(other),
        }
    }

    /// The raw `kTLVType_Error` byte; [`Self::from_code`] reverses it.
    #[must_use]
    pub fn code(self) -> u8 {
        match self {
            Self::Unknown => 0x01,
            Self::Authentication => 0x02,
            Self::Backoff => 0x03,
            Self::MaxPeers => 0x04,
            Self::MaxTries => 0x05,
            Self::Unavailable => 0x06,
            Self::Busy => 0x07,
            Self::Other(code) => code,
        }
    }

    /// A message fit to show a user, phrased around what they can do about it.
    #[must_use]
    pub fn user_message(self) -> &'static str {
        match self {
            Self::Authentication => "The PIN did not match. Try again.",
            Self::Backoff => "Too many attempts. Wait a moment before trying again.",
            Self::MaxPeers => "This device has no pairing slots left.",
            Self::MaxTries => "Too many failed attempts. Reset the device to pair again.",
            Self::Unavailable => "This device is not accepting pairings right now.",
            Self::Busy => "This device is busy pairing with something else.",
            Self::Unknown | Self::Other(_) => "The device refused to pair.",
        }
    }
}

/// Bits of the HAP `kTLVType_Flags` field that matter to AirPlay.
pub mod flags {
    /// Transient: derive session keys without storing a pairing on the device.
    pub const TRANSIENT: u32 = 0x0000_0010;
    /// Split: the setup and verify halves are separate exchanges.
    pub const SPLIT: u32 = 0x0100_0000;
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_pairing_error_code_round_trips() {
        for code in 0..=u8::MAX {
            assert_eq!(super::PairingError::from_code(code).code(), code);
        }
    }
}
