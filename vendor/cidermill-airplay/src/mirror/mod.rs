//! AirPlay screen mirroring, sans-io: stream `SETUP`, data-connection packets, the H.264 bitstream
//! around them, and the stream cipher. Behind the `mirror` feature (adds `aes` and `ctr`).
//!
//! - [`packet`]: the 128-byte header. [`avc`]: `avcC`, SPS reader, Annex B / AVCC.
//! - [`key`]: base key, stream key and IV, continuous AES-128-CTR. [`setup`]: the `type: 110`
//!   request and reply.
//! - [`reader`] / [`writer`]: the receiver's and sender's packet streams, every bound enforced.
//!
//! This crate never unwraps, wraps or describes an Apple sender's wrapped key (`ekey`);
//! [`setup::MirrorMarker::WrappedKey`] only recognises it. Layout is ASSUMED from reading UxPlay;
//! unproven against an Apple device.

pub mod avc;
pub mod key;
pub mod packet;
pub mod reader;
pub mod setup;
pub mod writer;

pub use avc::{AvcConfig, SpsInfo};
pub use key::{MirrorKey, StreamCipher, StreamKey};
pub use packet::{PacketHeader, PayloadKind};
pub use reader::{MirrorEvent, MirrorStreamReader, ReaderStats};
pub use setup::{MirrorMarker, MirrorStreamReply, MirrorStreamSetup};
pub use writer::{MirrorStreamWriter, OutgoingPacket};

/// The stream `type` of a screen-mirroring stream.
pub const STREAM_TYPE: u64 = 110;

/// Bytes of header before every payload.
pub const HEADER_LEN: usize = 128;

/// The largest video payload accepted (`type` 0). ASSUMED.
pub const MAX_FRAME_BYTES: u32 = 4 * 1024 * 1024;

/// The largest codec record accepted (`type` 1). ASSUMED.
pub const MAX_CODEC_BYTES: u32 = 64 * 1024;

/// The largest streaming report accepted (`type` 5), skipped unread. ASSUMED.
pub const MAX_REPORT_BYTES: u32 = 64 * 1024;

/// NAL units in one access unit, at most. ASSUMED.
pub const MAX_NALS_PER_FRAME: usize = 256;

/// Packets in any one second, at most. ASSUMED.
pub const MAX_PACKETS_PER_SECOND: u32 = 300;

/// Payload bytes in any one second, at most. ASSUMED.
pub const MAX_BYTES_PER_SECOND: u64 = 8 * 1024 * 1024;

/// The smallest picture side accepted, in pixels.
pub const MIN_SIDE: u32 = 16;

/// The largest picture side accepted, in pixels. ASSUMED.
pub const MAX_SIDE: u32 = 4096;

/// The largest picture area accepted, in pixels (4096 × 2304). ASSUMED.
pub const MAX_AREA: u64 = 4096 * 2304;
