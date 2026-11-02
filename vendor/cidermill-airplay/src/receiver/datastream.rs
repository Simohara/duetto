//! The receiver's end of a MediaRemote data channel (`type: 130`), sans-io.
//!
//! Reads HAP-framed [`crate::datastream`] frames with the sender's output key
//! ([`crate::datastream::keys`]), answers every `sync` with its `rply`, and hands out MediaRemote
//! messages undecoded. Unproven on the wire: no sender has opened one to us.

use crate::cipher::EncryptedTransport;
use crate::datastream::{keys, unwrap_messages, DataFrame, DataFrameDecoder, DecodedFrame};
use crate::error::Result;

/// What one read produced.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DataStreamRead {
    /// Bytes to write back (the sealed `rply`s).
    pub reply: Vec<u8>,
    /// Frames received: `(message type, sequence number, payload bytes)`.
    pub frames: Vec<(String, u64, usize)>,
    /// MediaRemote messages found in the frames' payloads (raw protobuf).
    pub messages: Vec<Vec<u8>>,
    /// Bytes the frame decoder had to drop.
    pub dropped: usize,
}

/// One data channel.
pub struct DataStreamServer {
    transport: EncryptedTransport,
    decoder: DataFrameDecoder,
}

impl std::fmt::Debug for DataStreamServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DataStreamServer").finish_non_exhaustive()
    }
}

impl DataStreamServer {
    /// The channel for `seed`, from the session's shared secret.
    pub fn new(shared_secret: &[u8], seed: i64) -> Result<Self> {
        let (sender_write, sender_read) = keys(shared_secret, seed)?;
        Ok(Self {
            transport: EncryptedTransport::from_keys(&sender_read, &sender_write),
            decoder: DataFrameDecoder::new(),
        })
    }

    /// Feeds bytes read from the socket.
    pub fn receive(&mut self, bytes: &[u8]) -> Result<DataStreamRead> {
        self.transport.push(bytes);
        while let Some(plain) = self.transport.open_next()? {
            self.decoder.push(&plain);
        }
        let mut read = DataStreamRead::default();
        while let Some(decoded) = self.decoder.next_frame() {
            match decoded {
                DecodedFrame::Frame(frame) => {
                    let kind = String::from_utf8_lossy(&frame.message_type)
                        .trim_end_matches('\0')
                        .to_owned();
                    read.frames.push((kind, frame.seqno, frame.payload.len()));
                    if let Ok(Some(messages)) = unwrap_messages(&frame.payload) {
                        read.messages.extend(messages);
                    }
                    if frame.is_request() {
                        let reply = DataFrame::reply(frame.seqno).encode()?;
                        read.reply.extend(self.transport.seal(&reply)?);
                    }
                }
                DecodedFrame::Dropped { bytes } => read.dropped += bytes,
            }
        }
        Ok(read)
    }
}
