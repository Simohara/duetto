//! The receiver half of AirPlay 2, sans-io: what a sender speaks, answered. Nothing here opens a
//! socket; mDNS, listeners, UDP and the PCM sink are the host's. This crate never answers
//! `/fp-setup`; a host may, through a [`crate::extension::ReceiverExtension`].
//!
//! - [`identity`], [`config`], [`controllers`], [`advertisement`]: who the receiver is, its policy,
//!   paired senders, TXT records.
//! - [`pairing`], [`pin`]: HAP pair-setup (transient and PIN) and pair-verify; the PIN gate.
//! - [`connection`]: one control connection, bytes in and out, [`ReceiverEvent`]s for the host.
//! - [`RealtimeStream`], [`BufferedStream`]: a stream end to end, datagrams or TCP bytes in, PCM
//!   out with when to play it ([`stream`]); the host keeps its sockets, threads and sink.
//! - [`audio`], [`buffered`], [`clock`], [`playout`]: the parts they are built from, for a host
//!   that assembles its own: audio receive, clock tracking, playout timing.
//! - [`datastream`]: the MediaRemote data channel (`type: 130`).
//!
//! Observed with this crate's own sender and pyatv 0.18.0 (transient and PIN pairing, ALAC and
//! LPCM). No Apple sender has completed a session with it; that is ASSUMED to work the same.

pub mod advertisement;
pub mod audio;
pub mod buffered;
pub mod buffered_stream;
pub mod clock;
pub mod config;
pub mod connection;
pub mod controllers;
pub mod datastream;
pub mod identity;
pub mod pairing;
pub mod pin;
pub mod playout;
pub mod realtime_stream;
pub mod stream;

pub use advertisement::{ReceiverAdvertisement, STATUS_PIN_REQUIRED};
#[cfg(feature = "mirror")]
pub use audio::AccessUnitPacket;
pub use audio::{AudioStreamFormat, PacketDecoder, PcmPacket, RealtimeReceiver, RealtimeStats};
pub use buffered::{BufferedPacket, BufferedReceiver, BufferedStats};
pub use buffered_stream::{
    AnchorChange, BufferedStream, BufferedStreamConfig, BufferedStreamStats, PtpReading,
};
pub use clock::{ClockTracker, DriftEstimate};
pub use config::{ReceiverConfig, ReceiverConfigBuilder, ReceiverSwitches};
#[cfg(feature = "mirror")]
pub use connection::AesCbcAudioKey;
pub use connection::{
    AudioStreamSetup, BufferedAudioStreamSetup, EncryptedBy, PortAllocator, PortKind,
    ReceiverConnection, ReceiverEvent, ReceiverProgress, SessionTiming, MAX_PHOTO_BYTES,
    MAX_PLAY_URL_BYTES, MAX_SESSION_SETUPS_PER_CONNECTION, MAX_STREAMS_PER_CONNECTION,
    URL_PLAYBACK_MAX_PER_SECOND,
};
pub use controllers::{ControllerStore, MemoryControllerStore, PairedController};
pub use datastream::{DataStreamRead, DataStreamServer};
pub use identity::ReceiverIdentity;
pub use pin::{PinAfterFailure, PinClaim, PinGate, PinNotice, PinRefusal, PinStart};
pub use playout::{Playout, PlayoutScheduler, PlayoutStats};
pub use realtime_stream::{RealtimeStream, RealtimeStreamConfig, RealtimeStreamStats};
pub use stream::{ScheduledPacket, SinkDelay, StreamNotice, StreamOutput};
