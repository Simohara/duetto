//! AirPlay 1's `et` 1: a random AES-128 key, sent in the `ANNOUNCE`'s SDP wrapped with an RSA
//! **public** key (`a=rsaaeskey`, RSAES-OAEP with SHA-1 and MGF1-SHA-1, empty label — RFC 8017
//! §7.1.1), the IV beside it in the clear (`a=aesiv`), and each packet's audio AES-128-CBC
//! encrypted over its whole 16-byte blocks with the IV reset for every packet and the trailing
//! remainder left clear.
//!
//! The only key that receivers hold the private half of is the one an AirPort Express carries
//! ([`AIRPORT_EXPRESS_MODULUS`], published by every open sender since 2004); this crate holds the
//! public half only, so it can send `et` 1 and never receive it. The OAEP here is written from RFC
//! 8017; the wire behaviour (SHA-1, unpadded base64, the IV reset per packet, whole blocks only)
//! was read from OwnTone's `src/outputs/raop.c` (GPL-2.0-or-later, read for behaviour, nothing
//! ported). Encryption with a public key holds no secret, so the big-integer arithmetic need not be
//! constant time.

use aes::cipher::KeyIvInit;
use cbc::cipher::{block_padding::NoPadding, BlockModeEncrypt};
use num_bigint::BigUint;
use rand_core::CryptoRng;
use sha1::{Digest, Sha1};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{AirPlayError, Result};

/// The AirPort Express RSA public key's modulus, big-endian (2048 bits). Its exponent is
/// [`AIRPORT_EXPRESS_EXPONENT`].
pub const AIRPORT_EXPRESS_MODULUS: [u8; 256] = [
    0xe7, 0xd7, 0x44, 0xf2, 0xa2, 0xe2, 0x78, 0x8b, 0x6c, 0x1f, 0x55, 0xa0, 0x8e, 0xb7, 0x05, 0x44,
    0xa8, 0xfa, 0x79, 0x45, 0xaa, 0x8b, 0xe6, 0xc6, 0x2c, 0xe5, 0xf5, 0x1c, 0xbd, 0xd4, 0xdc, 0x68,
    0x42, 0xfe, 0x3d, 0x10, 0x83, 0xdd, 0x2e, 0xde, 0xc1, 0xbf, 0xd4, 0x25, 0x2d, 0xc0, 0x2e, 0x6f,
    0x39, 0x8b, 0xdf, 0x0e, 0x61, 0x48, 0xea, 0x84, 0x85, 0x5e, 0x2e, 0x44, 0x2d, 0xa6, 0xd6, 0x26,
    0x64, 0xf6, 0x74, 0xa1, 0xf3, 0x04, 0x92, 0x9a, 0xde, 0x4f, 0x68, 0x93, 0xef, 0x2d, 0xf6, 0xe7,
    0x11, 0xa8, 0xc7, 0x7a, 0x0d, 0x91, 0xc9, 0xd9, 0x80, 0x82, 0x2e, 0x50, 0xd1, 0x29, 0x22, 0xaf,
    0xea, 0x40, 0xea, 0x9f, 0x0e, 0x14, 0xc0, 0xf7, 0x69, 0x38, 0xc5, 0xf3, 0x88, 0x2f, 0xc0, 0x32,
    0x3d, 0xd9, 0xfe, 0x55, 0x15, 0x5f, 0x51, 0xbb, 0x59, 0x21, 0xc2, 0x01, 0x62, 0x9f, 0xd7, 0x33,
    0x52, 0xd5, 0xe2, 0xef, 0xaa, 0xbf, 0x9b, 0xa0, 0x48, 0xd7, 0xb8, 0x13, 0xa2, 0xb6, 0x76, 0x7f,
    0x6c, 0x3c, 0xcf, 0x1e, 0xb4, 0xce, 0x67, 0x3d, 0x03, 0x7b, 0x0d, 0x2e, 0xa3, 0x0c, 0x5f, 0xff,
    0xeb, 0x06, 0xf8, 0xd0, 0x8a, 0xdd, 0xe4, 0x09, 0x57, 0x1a, 0x9c, 0x68, 0x9f, 0xef, 0x10, 0x72,
    0x88, 0x55, 0xdd, 0x8c, 0xfb, 0x9a, 0x8b, 0xef, 0x5c, 0x89, 0x43, 0xef, 0x3b, 0x5f, 0xaa, 0x15,
    0xdd, 0xe6, 0x98, 0xbe, 0xdd, 0xf3, 0x59, 0x96, 0x03, 0xeb, 0x3e, 0x6f, 0x61, 0x37, 0x2b, 0xb6,
    0x28, 0xf6, 0x55, 0x9f, 0x59, 0x9a, 0x78, 0xbf, 0x50, 0x06, 0x87, 0xaa, 0x7f, 0x49, 0x76, 0xc0,
    0x56, 0x2d, 0x41, 0x29, 0x56, 0xf8, 0x98, 0x9e, 0x18, 0xa6, 0x35, 0x5b, 0xd8, 0x15, 0x97, 0x82,
    0x5e, 0x0f, 0xc8, 0x75, 0x34, 0x3e, 0xc7, 0x82, 0x11, 0x76, 0x25, 0xcd, 0xbf, 0x98, 0x44, 0x7b,
];

/// The AirPort Express RSA public key's exponent.
pub const AIRPORT_EXPRESS_EXPONENT: u32 = 65_537;

/// SHA-1's output length, OAEP's `hLen`.
const HASH_LEN: usize = 20;

/// An RSA public key, for RSAES-OAEP encryption only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsaPublicKey {
    modulus: BigUint,
    exponent: BigUint,
    /// The modulus's length in bytes, RFC 8017's `k`.
    len: usize,
}

impl RsaPublicKey {
    /// A key from its big-endian modulus and exponent.
    ///
    /// # Errors
    ///
    /// A modulus under 512 bits or even, or an exponent under 3 or even.
    pub fn new(modulus: &[u8], exponent: &[u8]) -> Result<Self> {
        let n = BigUint::from_bytes_be(modulus);
        let e = BigUint::from_bytes_be(exponent);
        let three = BigUint::from(3u8);
        if n.bits() < 512 || !n.bit(0) || e < three || !e.bit(0) {
            return Err(AirPlayError::Protocol(
                "an RSA public key needs an odd modulus of 512 bits or more and an odd exponent of 3 or more"
                    .to_owned(),
            ));
        }
        let len = usize::try_from(n.bits().div_ceil(8)).unwrap_or(usize::MAX);
        Ok(Self {
            modulus: n,
            exponent: e,
            len,
        })
    }

    /// The AirPort Express key ([`AIRPORT_EXPRESS_MODULUS`], [`AIRPORT_EXPRESS_EXPONENT`]).
    #[must_use]
    pub fn airport_express() -> Self {
        Self::new(
            &AIRPORT_EXPRESS_MODULUS,
            &AIRPORT_EXPRESS_EXPONENT.to_be_bytes(),
        )
        .expect("the AirPort Express key is a valid RSA public key")
    }

    /// The modulus's length in bytes: the length of every ciphertext.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Never: a key is at least 64 bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// RSAES-OAEP-ENCRYPT (RFC 8017 §7.1.1) with SHA-1, MGF1-SHA-1 and an empty label: `message`
    /// wrapped under this key, `self.len()` bytes, the seed drawn from `rng`.
    ///
    /// # Errors
    ///
    /// A message longer than `k - 2·hLen - 2` bytes.
    pub fn encrypt_oaep_sha1(&self, message: &[u8], rng: &mut dyn CryptoRng) -> Result<Vec<u8>> {
        let mut seed = [0u8; HASH_LEN];
        rng.fill_bytes(&mut seed);
        let out = self.encrypt_oaep_sha1_with_seed(message, &seed);
        seed.zeroize();
        out
    }

    /// [`Self::encrypt_oaep_sha1`] with the seed given — deterministic, for test vectors.
    ///
    /// # Errors
    ///
    /// As [`Self::encrypt_oaep_sha1`].
    pub fn encrypt_oaep_sha1_with_seed(
        &self,
        message: &[u8],
        seed: &[u8; HASH_LEN],
    ) -> Result<Vec<u8>> {
        let k = self.len;
        if message.len() + 2 * HASH_LEN + 2 > k {
            return Err(AirPlayError::Protocol(format!(
                "an OAEP message under a {k}-byte key is at most {} bytes, got {}",
                k.saturating_sub(2 * HASH_LEN + 2),
                message.len()
            )));
        }
        // DB = lHash || PS || 0x01 || M, k - hLen - 1 bytes.
        let mut db = vec![0u8; k - HASH_LEN - 1];
        db[..HASH_LEN].copy_from_slice(&Sha1::digest([]));
        let one_at = db.len() - message.len() - 1;
        db[one_at] = 0x01;
        db[one_at + 1..].copy_from_slice(message);
        xor(&mut db, &mgf1_sha1(seed, k - HASH_LEN - 1));
        let mut masked_seed = *seed;
        xor(&mut masked_seed, &mgf1_sha1(&db, HASH_LEN));
        // EM = 0x00 || maskedSeed || maskedDB.
        let mut em = Vec::with_capacity(k);
        em.push(0);
        em.extend_from_slice(&masked_seed);
        em.extend_from_slice(&db);
        db.zeroize();
        let c = BigUint::from_bytes_be(&em).modpow(&self.exponent, &self.modulus);
        em.zeroize();
        // I2OSP(c, k).
        let bytes = c.to_bytes_be();
        let mut out = vec![0u8; k - bytes.len()];
        out.extend_from_slice(&bytes);
        Ok(out)
    }
}

fn xor(into: &mut [u8], mask: &[u8]) {
    for (byte, m) in into.iter_mut().zip(mask) {
        *byte ^= m;
    }
}

/// MGF1 (RFC 8017 B.2.1) with SHA-1.
fn mgf1_sha1(seed: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + HASH_LEN);
    let mut counter = 0u32;
    while out.len() < len {
        let mut hash = Sha1::new();
        hash.update(seed);
        hash.update(counter.to_be_bytes());
        out.extend_from_slice(&hash.finalize());
        counter += 1;
    }
    out.truncate(len);
    out
}

/// A session's AES-128 key and IV. Zeroed on drop; `Debug` shows nothing.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct RaopAesKey {
    key: [u8; 16],
    iv: [u8; 16],
}

impl std::fmt::Debug for RaopAesKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RaopAesKey(<redacted>)")
    }
}

impl RaopAesKey {
    /// A fresh key and IV from `rng`.
    pub fn generate(rng: &mut dyn CryptoRng) -> Self {
        let mut key = [0u8; 16];
        let mut iv = [0u8; 16];
        rng.fill_bytes(&mut key);
        rng.fill_bytes(&mut iv);
        Self { key, iv }
    }

    /// A given key and IV (tests).
    #[must_use]
    pub fn new(key: [u8; 16], iv: [u8; 16]) -> Self {
        Self { key, iv }
    }

    /// The key (to wrap; never log it).
    #[must_use]
    pub fn key(&self) -> &[u8; 16] {
        &self.key
    }

    /// The IV, sent in the clear.
    #[must_use]
    pub fn iv(&self) -> &[u8; 16] {
        &self.iv
    }

    /// Encrypts one packet's audio in place: AES-128-CBC from this IV over the whole 16-byte
    /// blocks, the trailing bytes left clear.
    pub fn encrypt_payload(&self, payload: &mut [u8]) {
        let whole = payload.len() / 16 * 16;
        if whole == 0 {
            return;
        }
        type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
        // Whole blocks only, so no padding can fail.
        let _ = Aes128CbcEnc::new((&self.key).into(), (&self.iv).into())
            .encrypt_padded::<NoPadding>(&mut payload[..whole], whole);
    }

    /// The two SDP lines: `a=rsaaeskey:` (this key wrapped under `public`) and `a=aesiv:`, both
    /// base64 without padding, each ending `\r\n`.
    ///
    /// # Errors
    ///
    /// A key too short for OAEP over 16 bytes.
    pub fn sdp_lines(&self, public: &RsaPublicKey, rng: &mut dyn CryptoRng) -> Result<String> {
        let wrapped = public.encrypt_oaep_sha1(&self.key, rng)?;
        Ok(format!(
            "a=rsaaeskey:{}\r\na=aesiv:{}\r\n",
            base64_unpadded(&wrapped),
            base64_unpadded(&self.iv)
        ))
    }
}

/// Base64 (RFC 4648 §4) with the `=` padding left off, as RAOP senders write it.
#[must_use]
pub fn base64_unpadded(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        for i in 0..=chunk.len() {
            out.push(char::from(ALPHABET[(n >> (18 - 6 * i) & 0x3F) as usize]));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_rfc_4648_without_padding() {
        // RFC 4648 §10's vectors, padding removed.
        for (input, expected) in [
            ("", ""),
            ("f", "Zg"),
            ("fo", "Zm8"),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg"),
            ("fooba", "Zm9vYmE"),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64_unpadded(input.as_bytes()), expected);
        }
    }

    #[test]
    fn the_airport_express_key_is_2048_bits_with_exponent_65537() {
        let key = RsaPublicKey::airport_express();
        assert_eq!(key.len(), 256);
        assert_eq!(key.exponent, BigUint::from(65_537u32));
        // OwnTone and every open sender write the modulus's base64 as `59dE8qLieItsH1Wgjr…`.
        assert!(base64_unpadded(&AIRPORT_EXPRESS_MODULUS).starts_with("59dE8qLieItsH1Wgjr"));
    }

    #[test]
    fn a_message_too_long_for_the_key_is_refused() {
        let key = RsaPublicKey::airport_express();
        assert!(key
            .encrypt_oaep_sha1_with_seed(&[0; 215], &[0; 20])
            .is_err());
        assert_eq!(
            key.encrypt_oaep_sha1_with_seed(&[0; 214], &[0; 20])
                .unwrap()
                .len(),
            256
        );
    }

    #[test]
    fn a_short_tail_is_left_clear() {
        let key = RaopAesKey::new([1; 16], [2; 16]);
        let mut short = [7u8; 15];
        key.encrypt_payload(&mut short);
        assert_eq!(short, [7u8; 15]);
        let mut longer = [7u8; 20];
        key.encrypt_payload(&mut longer);
        assert_ne!(longer[..16], [7u8; 16]);
        assert_eq!(longer[16..], [7u8; 4]);
    }

    #[test]
    fn a_bad_key_is_refused() {
        assert!(RsaPublicKey::new(&[0xFF; 32], &[1, 0, 1]).is_err());
        assert!(RsaPublicKey::new(&AIRPORT_EXPRESS_MODULUS, &[2]).is_err());
        let mut even = AIRPORT_EXPRESS_MODULUS;
        even[255] &= 0xFE;
        assert!(RsaPublicKey::new(&even, &[1, 0, 1]).is_err());
    }
}
