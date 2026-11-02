//! The mirroring stream's key: a 16-byte base key, the per-stream key and IV derived from it,
//! and the cipher.
//!
//! - Stream key and IV: `SHA-512(label ‖ decimal(streamConnectionID) ‖ base)[..16]`, labels
//!   `"AirPlayStreamKey"` / `"AirPlayStreamIV"`.
//! - Cipher: AES-128-CTR, all 128 counter bits big-endian, one keystream across every video
//!   payload in order; codec records, heartbeats and reports are clear and do not advance it.
//! - Base key: [`MirrorKey::from_pairing`] (two peers of this crate),
//!   [`MirrorKey::from_session_key`] (a key a receiver extension unwrapped) or
//!   [`MirrorKey::from_bytes`]. This crate never unwraps `ekey`.

use aes::cipher::{KeyIvInit, StreamCipher as _};
use sha2::{Digest, Sha512};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::Result;
use crate::pairing::hkdf_key;

/// The HKDF salt of [`MirrorKey::from_pairing`].
pub const PAIRING_KEY_SALT: &[u8] = b"Cidermill-Mirror-Salt";

/// The HKDF info of [`MirrorKey::from_pairing`], version 1
/// ([`super::setup::PAIRING_KEYED_VERSION`]).
pub const PAIRING_KEY_INFO: &[u8] = b"Cidermill-Mirror-Key-1";

/// The label hashed for the stream key.
pub const STREAM_KEY_LABEL: &str = "AirPlayStreamKey";

/// The label hashed for the stream IV.
pub const STREAM_IV_LABEL: &str = "AirPlayStreamIV";

type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;

/// A mirroring session's 16-byte base key. Zeroed on drop; its `Debug` shows nothing.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct MirrorKey([u8; 16]);

impl std::fmt::Debug for MirrorKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MirrorKey(<redacted>)")
    }
}

impl MirrorKey {
    /// A base key from its bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// The base key `SHA-512(session_key ‖ ecdh_secret)[..16]`: `session_key` is what a receiver
    /// extension unwrapped ([`crate::extension::ExtensionSession::unwrap_session_key`]),
    /// `ecdh_secret` the pair-verify shared secret
    /// ([`crate::pairing::SessionKeys::shared_secret`]). Unproven on hardware.
    #[must_use]
    pub fn from_session_key(session_key: &[u8; 16], ecdh_secret: &[u8]) -> Self {
        let mut hash = Sha512::new();
        hash.update(session_key);
        hash.update(ecdh_secret);
        let mut digest: [u8; 64] = hash.finalize().into();
        let mut key = [0u8; 16];
        key.copy_from_slice(&digest[..16]);
        digest.zeroize();
        Self(key)
    }

    /// The base key two peers of this crate agree without sending it: HKDF-SHA512 of the pairing's
    /// shared secret ([`crate::pairing::SessionKeys::shared_secret`]), [`PAIRING_KEY_SALT`],
    /// [`PAIRING_KEY_INFO`].
    ///
    /// # Errors
    ///
    /// HKDF refusing the expansion (it does not for these lengths).
    pub fn from_pairing(shared_secret: &[u8]) -> Result<Self> {
        let mut wide = hkdf_key(shared_secret, PAIRING_KEY_SALT, PAIRING_KEY_INFO)?;
        let mut key = [0u8; 16];
        key.copy_from_slice(&wide[..16]);
        wide.zeroize();
        Ok(Self(key))
    }

    /// The bytes. Never log them.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// The key and IV for one stream.
    #[must_use]
    pub fn stream(&self, stream_connection_id: u64) -> StreamKey {
        let derive = |label: &str| {
            let mut hash = Sha512::new();
            hash.update(label.as_bytes());
            hash.update(stream_connection_id.to_string().as_bytes());
            hash.update(self.0);
            let mut digest: [u8; 64] = hash.finalize().into();
            let mut out = [0u8; 16];
            out.copy_from_slice(&digest[..16]);
            digest.zeroize();
            out
        };
        StreamKey {
            key: derive(STREAM_KEY_LABEL),
            iv: derive(STREAM_IV_LABEL),
        }
    }
}

/// One stream's AES-128 key and initial counter block.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct StreamKey {
    /// The AES-128 key.
    pub key: [u8; 16],
    /// The initial counter block.
    pub iv: [u8; 16],
}

impl std::fmt::Debug for StreamKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StreamKey(<redacted>)")
    }
}

impl StreamKey {
    /// A fresh cipher at the start of this stream's keystream.
    #[must_use]
    pub fn cipher(&self) -> StreamCipher {
        StreamCipher {
            inner: Aes128Ctr::new(&self.key.into(), &self.iv.into()),
        }
    }
}

/// The stream's one continuous AES-128-CTR keystream. Encrypting and decrypting are the same
/// operation; every call continues where the last one stopped, mid-block or not.
pub struct StreamCipher {
    inner: Aes128Ctr,
}

impl std::fmt::Debug for StreamCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StreamCipher(<redacted>)")
    }
}

impl StreamCipher {
    /// XORs the next `data.len()` bytes of keystream into `data`, in place.
    ///
    /// Cannot fail: a 128-bit counter outlasts any stream.
    pub fn apply(&mut self, data: &mut [u8]) {
        self.inner.apply_keystream(data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_keystream_continues_across_calls_of_any_length() {
        let key = MirrorKey::from_bytes([7; 16]).stream(42);
        let mut whole = vec![0u8; 100];
        key.cipher().apply(&mut whole);
        for cut in 0..=100 {
            let mut pieces = vec![0u8; 100];
            let mut cipher = key.cipher();
            let (a, b) = pieces.split_at_mut(cut);
            cipher.apply(a);
            cipher.apply(b);
            assert_eq!(pieces, whole, "split at {cut}");
        }
    }

    #[test]
    fn the_counter_carries_across_all_128_bits() {
        // All-ones IV: the second block's counter is zero; a 64-bit counter would not give that.
        let key = StreamKey {
            key: [0x2B; 16],
            iv: [0xFF; 16],
        };
        let mut stream = [0u8; 32];
        key.cipher().apply(&mut stream);
        let zero_iv = StreamKey {
            key: [0x2B; 16],
            iv: [0; 16],
        };
        let mut first_block_of_zero = [0u8; 16];
        zero_iv.cipher().apply(&mut first_block_of_zero);
        assert_eq!(stream[16..], first_block_of_zero);
    }

    #[test]
    fn keys_never_reach_a_debug_string() {
        let key = MirrorKey::from_bytes([0xAB; 16]);
        let text = format!("{key:?} {:?} {:?}", key.stream(1), key.stream(1).cipher());
        assert!(!text.to_lowercase().contains("ab"), "{text}");
    }
}
