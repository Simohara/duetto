//! The HAP encrypted framing the AirPlay control channel switches to after pair-verify.
//!
//! The port-7000 connection is plaintext up to pair-verify M4 and ChaCha20-Poly1305 after it
//! (observed on `AppleTV14,1`). A frame is a 2-byte little-endian plaintext length (also the AEAD
//! associated data), the ciphertext, then a 16-byte Poly1305 tag. What we send is split at
//! [`MAX_FRAME_PLAINTEXT`]; what we receive may be any length the prefix can say
//! ([`MAX_INBOUND_FRAME_PLAINTEXT`]). Each direction has its own key and counter, the counter is the nonce
//! ([`hap_nonce`]), and a decrypt failure is terminal.
//!
//! Sans-io: [`EncryptedTransport::seal`] makes wire bytes; [`EncryptedTransport::push`] and
//! [`EncryptedTransport::open_next`] recover plaintext. Layout: pyatv 0.18.0 `HAPSession`.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};

use super::pairing::SessionKeys;
use crate::error::{AirPlayError, Result};

/// Largest plaintext in a frame we seal; fixed by the protocol, and what receivers take.
pub const MAX_FRAME_PLAINTEXT: usize = 1024;

/// Largest plaintext in a frame we open: whatever the 16-bit length prefix can carry.
///
/// OBSERVED: a HomePod (`AudioAccessory5,1`, build 24J361) sent a 4906-byte frame on the
/// `MediaRemote` data channel right after `DEVICE_INFO`, so a receiver does not keep to
/// [`MAX_FRAME_PLAINTEXT`]. pyatv 0.18.0's `HAPSession.decrypt` takes any length too. The bound
/// holds by construction, so no length prefix can claim more than this.
pub const MAX_INBOUND_FRAME_PLAINTEXT: usize = u16::MAX as usize;

/// Length of the Poly1305 tag appended to every frame.
pub const TAG_LEN: usize = 16;

/// Length of the little-endian length prefix, which doubles as the AEAD associated data.
pub const LENGTH_PREFIX_LEN: usize = 2;

/// The nonce for a frame: four zero bytes, then the counter as eight little-endian bytes.
///
/// Observed on an Apple TV. Not the Companion layout (12-byte little-endian counter); the two
/// agree only for counter 0.
#[must_use]
pub fn hap_nonce(counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&counter.to_le_bytes());
    nonce
}

/// Most undecrypted inbound bytes held before the peer is declared hostile.
pub const MAX_PENDING_BYTES: usize = 4 * 1024 * 1024;

/// The post-pair-verify control-channel cipher: two keys, two independent counters.
pub struct EncryptedTransport {
    write: ChaCha20Poly1305,
    read: ChaCha20Poly1305,
    /// Frames sent; the nonce source. `wrapping_add` is safe: 2^64 frames is unreachable.
    out_counter: u64,
    /// Frames received.
    in_counter: u64,
    pending: Vec<u8>,
    poisoned: bool,
}

impl std::fmt::Debug for EncryptedTransport {
    /// Opaque about the keys.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedTransport")
            .field("out_counter", &self.out_counter)
            .field("in_counter", &self.in_counter)
            .field("pending", &self.pending.len())
            .field("poisoned", &self.poisoned)
            .finish_non_exhaustive()
    }
}

impl EncryptedTransport {
    /// Builds the transport from the keys pair-verify derived.
    ///
    /// `write_key` encrypts what we send and `read_key` decrypts what we receive; swapping them
    /// makes every frame fail to open.
    #[must_use]
    pub fn new(keys: &SessionKeys) -> Self {
        Self::from_keys(&keys.write_key, &keys.read_key)
    }

    /// Builds the transport from raw keys.
    #[must_use]
    pub fn from_keys(write_key: &[u8; 32], read_key: &[u8; 32]) -> Self {
        Self {
            write: ChaCha20Poly1305::new(write_key.into()),
            read: ChaCha20Poly1305::new(read_key.into()),
            out_counter: 0,
            in_counter: 0,
            pending: Vec::new(),
            poisoned: false,
        }
    }

    /// Encrypts a whole message across as many frames as needed. An empty message still
    /// produces one frame, keeping the counters in step with the peer.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(plaintext.len() + 64);
        let mut chunks = plaintext.chunks(MAX_FRAME_PLAINTEXT);
        let mut wrote_any = false;
        for chunk in chunks.by_ref() {
            self.seal_frame(chunk, &mut out)?;
            wrote_any = true;
        }
        if !wrote_any {
            self.seal_frame(&[], &mut out)?;
        }
        Ok(out)
    }

    fn seal_frame(&mut self, chunk: &[u8], out: &mut Vec<u8>) -> Result<()> {
        // `chunk` is at most MAX_FRAME_PLAINTEXT, so this cannot truncate.
        let length = u16::try_from(chunk.len()).map_err(|_| {
            AirPlayError::Protocol("control frame is longer than 64 KiB".to_owned())
        })?;
        let prefix = length.to_le_bytes();
        let nonce = hap_nonce(self.out_counter);
        let sealed = self
            .write
            .encrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: chunk,
                    aad: &prefix,
                },
            )
            .map_err(|_| AirPlayError::Protocol("control frame seal failed".to_owned()))?;
        self.out_counter = self.out_counter.wrapping_add(1);
        out.extend_from_slice(&prefix);
        out.extend_from_slice(&sealed);
        Ok(())
    }

    /// Adds bytes read from the socket. Frames are recovered by [`Self::open_next`].
    pub fn push(&mut self, bytes: &[u8]) {
        self.pending.extend_from_slice(bytes);
    }

    /// How many undecrypted bytes are held.
    #[must_use]
    pub fn buffered(&self) -> usize {
        self.pending.len()
    }

    /// The undecrypted bytes, for diagnostics.
    #[must_use]
    pub fn pending_bytes(&self) -> &[u8] {
        &self.pending
    }

    /// Decrypts the next complete frame, or `None` when one has not arrived yet.
    ///
    /// A failure to open is terminal: the transport refuses everything afterwards rather than
    /// resynchronising.
    pub fn open_next(&mut self) -> Result<Option<Vec<u8>>> {
        if self.poisoned {
            return Err(AirPlayError::Protocol(
                "the encrypted control channel failed to authenticate a frame and cannot continue"
                    .to_owned(),
            ));
        }
        if self.pending.len() > MAX_PENDING_BYTES {
            self.poisoned = true;
            return Err(AirPlayError::Protocol(
                "receiver sent more than the encrypted-frame cap without completing a frame"
                    .to_owned(),
            ));
        }
        if self.pending.len() < LENGTH_PREFIX_LEN {
            return Ok(None);
        }

        let prefix = [self.pending[0], self.pending[1]];
        // At most `MAX_INBOUND_FRAME_PLAINTEXT` by construction. A stream that is not framed with
        // the peer claims some length, waits for that many bytes and then fails the AEAD tag,
        // which poisons the channel below. The wait is bounded by that one frame (at most
        // 65 553 bytes with prefix and tag); a peer that stops mid-frame looks the same as one idle
        // between frames.
        let length = usize::from(u16::from_le_bytes(prefix));
        let total = LENGTH_PREFIX_LEN + length + TAG_LEN;
        if self.pending.len() < total {
            return Ok(None);
        }

        let nonce = hap_nonce(self.in_counter);
        let opened = self
            .read
            .decrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: &self.pending[LENGTH_PREFIX_LEN..total],
                    aad: &prefix,
                },
            )
            .map_err(|_| AirPlayError::Decrypt);
        let opened = match opened {
            Ok(bytes) => bytes,
            Err(e) => {
                self.poisoned = true;
                return Err(e);
            }
        };

        self.pending.drain(..total);
        self.in_counter = self.in_counter.wrapping_add(1);
        Ok(Some(opened))
    }

    /// Frames sent, for diagnostics.
    #[must_use]
    pub fn frames_sent(&self) -> u64 {
        self.out_counter
    }

    /// How many frames have been received.
    #[must_use]
    pub fn frames_received(&self) -> u64 {
        self.in_counter
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (EncryptedTransport, EncryptedTransport) {
        let ours = [7u8; 32];
        let theirs = [9u8; 32];
        (
            EncryptedTransport::from_keys(&ours, &theirs),
            // The peer's write key is our read key and vice versa.
            EncryptedTransport::from_keys(&theirs, &ours),
        )
    }

    #[test]
    fn a_frame_is_a_little_endian_length_then_ciphertext_and_tag() {
        let (mut sender, _) = pair();
        let framed = sender.seal(b"hello").expect("seal");
        assert_eq!(&framed[..2], &[5, 0]);
        assert_eq!(framed.len(), LENGTH_PREFIX_LEN + 5 + TAG_LEN);
    }

    #[test]
    fn a_message_longer_than_one_frame_is_split_on_the_protocol_boundary() {
        let (mut sender, mut receiver) = pair();
        let payload = vec![0xABu8; MAX_FRAME_PLAINTEXT * 2 + 37];
        let framed = sender.seal(&payload).expect("seal");
        assert_eq!(sender.frames_sent(), 3);
        assert_eq!(
            framed.len(),
            3 * (LENGTH_PREFIX_LEN + TAG_LEN) + payload.len()
        );

        receiver.push(&framed);
        let mut recovered = Vec::new();
        while let Some(frame) = receiver.open_next().expect("open") {
            recovered.extend_from_slice(&frame);
        }
        assert_eq!(recovered, payload);
    }

    #[test]
    fn a_frame_split_across_reads_is_buffered_rather_than_failed() {
        let (mut sender, mut receiver) = pair();
        let framed = sender.seal(b"GET /info RTSP/1.0\r\n\r\n").expect("seal");
        for byte in &framed[..framed.len() - 1] {
            receiver.push(&[*byte]);
            assert_eq!(receiver.open_next().expect("partial"), None);
        }
        receiver.push(&framed[framed.len() - 1..]);
        assert_eq!(
            receiver.open_next().expect("complete"),
            Some(b"GET /info RTSP/1.0\r\n\r\n".to_vec())
        );
    }

    #[test]
    fn each_frame_uses_a_fresh_nonce_so_identical_payloads_differ_on_the_wire() {
        let (mut sender, _) = pair();
        let first = sender.seal(b"same").expect("first");
        let second = sender.seal(b"same").expect("second");
        assert_ne!(first, second, "counter reuse would leak the keystream");
    }

    #[test]
    fn a_tampered_frame_poisons_the_channel_rather_than_resynchronising() {
        let (mut sender, mut receiver) = pair();
        let mut framed = sender.seal(b"payload").expect("seal");
        let last = framed.len() - 1;
        framed[last] ^= 0x01;
        receiver.push(&framed);
        assert!(receiver.open_next().is_err());
        // A good frame is still refused afterwards.
        let good = sender.seal(b"payload").expect("seal");
        receiver.push(&good);
        assert!(receiver.open_next().is_err());
    }

    /// A frame the peer sealed as one piece, at `length` plaintext bytes.
    fn one_frame(sender: &mut EncryptedTransport, length: usize) -> (Vec<u8>, Vec<u8>) {
        let plain: Vec<u8> = (0..length).map(|i| (i % 251) as u8).collect();
        let mut out = Vec::new();
        sender.seal_frame(&plain, &mut out).expect("seal");
        (plain, out)
    }

    #[test]
    fn a_frame_over_the_sealing_size_opens_even_split_across_reads() {
        // OBSERVED: a HomePod's 4906-byte frame.
        let (mut sender, mut receiver) = pair();
        let (plain, wire) = one_frame(&mut sender, 4906);
        let (second, wire2) = one_frame(&mut sender, 5);
        let all = [wire, wire2].concat();
        for chunk in all.chunks(333) {
            receiver.push(chunk);
        }
        assert_eq!(receiver.open_next().expect("open"), Some(plain));
        assert_eq!(receiver.open_next().expect("open"), Some(second));
        assert_eq!(receiver.open_next().expect("open"), None);

        // And a byte at a time up to the last one.
        let (mut sender, mut receiver) = pair();
        let (plain, wire) = one_frame(&mut sender, 4906);
        for byte in &wire[..wire.len() - 1] {
            receiver.push(&[*byte]);
            assert_eq!(receiver.open_next().expect("partial"), None);
        }
        receiver.push(&wire[wire.len() - 1..]);
        assert_eq!(receiver.open_next().expect("complete"), Some(plain));
    }

    #[test]
    fn the_largest_frame_a_prefix_can_say_opens() {
        let (mut sender, mut receiver) = pair();
        let (plain, wire) = one_frame(&mut sender, MAX_INBOUND_FRAME_PLAINTEXT);
        assert_eq!(plain.len(), 65_535);
        receiver.push(&wire);
        assert_eq!(receiver.open_next().expect("open"), Some(plain));
    }

    #[test]
    fn a_stream_that_is_not_framed_waits_then_fails_the_tag_and_poisons() {
        let (_, mut receiver) = pair();
        receiver.push(&[0xFF, 0xFF]);
        // Claims 65 535 bytes: not an error until they arrive.
        assert_eq!(receiver.open_next().expect("waiting"), None);
        receiver.push(&vec![0x5A; MAX_INBOUND_FRAME_PLAINTEXT + TAG_LEN]);
        assert!(receiver.open_next().is_err());
        assert!(receiver.open_next().is_err(), "poisoned");
    }

    #[test]
    fn a_peer_that_never_completes_a_frame_is_cut_off_at_the_buffer_cap() {
        let (_, mut receiver) = pair();
        receiver.push(&[0xFF, 0xFF]);
        receiver.push(&vec![0u8; MAX_PENDING_BYTES]);
        // 2 + MAX_PENDING_BYTES held; the claimed frame would have completed, so cap it first.
        let error = receiver.open_next().expect_err("cap");
        assert!(format!("{error}").contains("cap"), "{error}");
        assert!(receiver.open_next().is_err(), "poisoned");
    }

    #[test]
    fn arbitrary_bytes_never_panic() {
        let mut seed = 0x9E37_79B9_7F4A_7C15_u64;
        for len in 0..400usize {
            let (_, mut receiver) = pair();
            let bytes: Vec<u8> = (0..len)
                .map(|_| {
                    seed ^= seed << 13;
                    seed ^= seed >> 7;
                    seed ^= seed << 17;
                    (seed >> 40) as u8
                })
                .collect();
            receiver.push(&bytes);
            while let Ok(Some(_)) = receiver.open_next() {}
        }
    }

    #[test]
    fn an_empty_message_still_produces_a_frame() {
        let (mut sender, mut receiver) = pair();
        let framed = sender.seal(b"").expect("seal");
        assert_eq!(framed.len(), LENGTH_PREFIX_LEN + TAG_LEN);
        receiver.push(&framed);
        assert_eq!(receiver.open_next().expect("open"), Some(Vec::new()));
    }
}
