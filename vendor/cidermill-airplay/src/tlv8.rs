//! Sans-io TLV8 codec: the body format of the HAP `/pair-setup` and `/pair-verify` endpoints.
//!
//! One type byte, one length byte, the value; a value over 255 bytes is split across consecutive
//! items of the same type and stitched back by the reader. The input is unauthenticated, so the
//! reader allocates only for bytes present and caps the item count.

use crate::error::{AirPlayError, Result};

/// Maximum number of TLV items accepted in one message. The `0xFF` separator ([`tag::SEPARATOR`])
/// counts toward it.
pub const MAX_ITEMS: usize = 4096;

/// HAP TLV types used by AirPlay pairing (HomeKit Accessory Protocol table 5-6).
pub mod tag {
    /// Pairing method (see [`crate::Method`]).
    pub const METHOD: u8 = 0x00;
    /// Identifier of the pairing peer.
    pub const IDENTIFIER: u8 = 0x01;
    /// SRP salt.
    pub const SALT: u8 = 0x02;
    /// SRP or Curve25519 public key.
    pub const PUBLIC_KEY: u8 = 0x03;
    /// SRP proof.
    pub const PROOF: u8 = 0x04;
    /// ChaCha20-Poly1305 sealed sub-TLV.
    pub const ENCRYPTED_DATA: u8 = 0x05;
    /// Protocol step number (M1..M6).
    pub const STATE: u8 = 0x06;
    /// Error code (see [`crate::PairingError`]).
    pub const ERROR: u8 = 0x07;
    /// Seconds to wait before retrying.
    pub const RETRY_DELAY: u8 = 0x08;
    /// Certificate.
    pub const CERTIFICATE: u8 = 0x09;
    /// Ed25519 signature.
    pub const SIGNATURE: u8 = 0x0A;
    /// Pairing permissions.
    pub const PERMISSIONS: u8 = 0x0B;
    /// Non-final fragment.
    pub const FRAGMENT_DATA: u8 = 0x0C;
    /// Final fragment.
    pub const FRAGMENT_LAST: u8 = 0x0D;
    /// Friendly name of the pairing peer. Apple-specific, outside the HAP table: Companion
    /// pair-setup M5 carries an OPACK `{"name": ...}` here.
    pub const NAME: u8 = 0x11;
    /// Pairing flags (see [`crate::flags`]).
    pub const FLAGS: u8 = 0x13;
    /// Separates several pairings in one message.
    pub const SEPARATOR: u8 = 0xFF;
}

/// A decoded TLV8 message: types in wire order, each with its reassembled value.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tlv8 {
    items: Vec<(u8, Vec<u8>)>,
}

impl Tlv8 {
    /// Creates an empty message.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends a value, fragmenting it on encode if it is longer than 255 bytes.
    pub fn push(&mut self, tag: u8, value: impl Into<Vec<u8>>) -> &mut Self {
        self.items.push((tag, value.into()));
        self
    }

    /// Appends a single-byte value, the common case for state, method and error.
    pub fn push_byte(&mut self, tag: u8, value: u8) -> &mut Self {
        self.push(tag, vec![value])
    }

    /// Appends a little-endian `u32`, the encoding HAP uses for the flags field.
    pub fn push_u32(&mut self, tag: u8, value: u32) -> &mut Self {
        self.push(tag, value.to_le_bytes().to_vec())
    }

    /// Appends a little-endian `u32` in the fewest bytes that hold it, as an iPhone writes the
    /// flags field (`13 01 10`; observed). [`Self::get_u32`] reads either width.
    pub fn push_u32_compact(&mut self, tag: u8, value: u32) -> &mut Self {
        let bytes = value.to_le_bytes();
        let used = bytes
            .iter()
            .rposition(|&b| b != 0)
            .map_or(1, |last| last + 1);
        self.push(tag, bytes[..used].to_vec())
    }

    /// Reads the first value with this tag.
    #[must_use]
    pub fn get(&self, tag: u8) -> Option<&[u8]> {
        self.items
            .iter()
            .find(|(item_tag, _)| *item_tag == tag)
            .map(|(_, value)| value.as_slice())
    }

    /// Reads a single-byte value.
    #[must_use]
    pub fn get_byte(&self, tag: u8) -> Option<u8> {
        match self.get(tag) {
            Some([single]) => Some(*single),
            _ => None,
        }
    }

    /// Reads a little-endian `u32`, tolerating the shorter encodings devices sometimes send.
    #[must_use]
    pub fn get_u32(&self, tag: u8) -> Option<u32> {
        let value = self.get(tag)?;
        if value.is_empty() || value.len() > 4 {
            return None;
        }
        let mut buf = [0u8; 4];
        buf[..value.len()].copy_from_slice(value);
        Some(u32::from_le_bytes(buf))
    }

    /// Every item, in wire order.
    pub fn iter(&self) -> impl Iterator<Item = (u8, &[u8])> {
        self.items
            .iter()
            .map(|(tag, value)| (*tag, value.as_slice()))
    }

    /// Number of items.
    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether the message is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Serializes to bytes, splitting long values into 255-byte fragments.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for (tag, value) in &self.items {
            if value.is_empty() {
                out.push(*tag);
                out.push(0);
                continue;
            }
            for chunk in value.chunks(255) {
                out.push(*tag);
                out.push(
                    u8::try_from(chunk.len()).expect("chunks(255) never yields more than 255"),
                );
                out.extend_from_slice(chunk);
            }
        }
        out
    }

    /// Parses bytes, reassembling fragmented values.
    ///
    /// Consecutive items with the same tag are one logical value. A tag that reappears after a
    /// different tag intervened starts a new item, which is how HAP distinguishes "this key is
    /// long" from "here are two pairings".
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut items: Vec<(u8, Vec<u8>)> = Vec::new();
        let mut offset = 0usize;

        while offset < bytes.len() {
            if items.len() >= MAX_ITEMS {
                return Err(AirPlayError::Protocol(
                    "TLV8 item count exceeded the cap".to_owned(),
                ));
            }

            let tag = bytes[offset];
            let Some(&length) = bytes.get(offset + 1) else {
                return Err(AirPlayError::Protocol(
                    "TLV8 item truncated at its length".to_owned(),
                ));
            };
            let length = usize::from(length);
            let start = offset + 2;
            let end = start
                .checked_add(length)
                .ok_or_else(|| AirPlayError::Protocol("TLV8 length overflows".to_owned()))?;
            if end > bytes.len() {
                return Err(AirPlayError::Protocol(
                    "TLV8 value runs past the end".to_owned(),
                ));
            }

            match items.last_mut() {
                // A 255-byte item followed by the same tag continues it; a shorter one ends it.
                Some((last_tag, last_value))
                    if *last_tag == tag
                        && last_value.len() % 255 == 0
                        && !last_value.is_empty() =>
                {
                    last_value.extend_from_slice(&bytes[start..end]);
                }
                _ => items.push((tag, bytes[start..end].to_vec())),
            }

            offset = end;
        }

        Ok(Self { items })
    }
}
