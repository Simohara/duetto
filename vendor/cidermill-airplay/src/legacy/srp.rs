//! SRP-6a for legacy AirPlay `/pair-setup-pin`: SHA-1 over the RFC 5054 2048-bit group, `g = 2`.
//!
//! ```text
//!   x   = H(salt | H(username | ":" | pin))
//!   k   = H(N | PAD(g))
//!   u   = H(PAD(A) | PAD(B))
//!   S   = (B - k * g^x) ^ (a + u*x)  mod N
//!   K   = H(S | 00 00 00 00) | H(S | 00 00 00 01)          (40 bytes, not H(S))
//!   M1  = H( (H(N) XOR H(g)) | H(username) | salt | A | B | K )
//!   M2  = H( A | M1 | K )
//! ```
//!
//! Non-textbook: `K` is two SHA-1 blocks, and hash inputs (including `H(username)`) are minimal
//! big-endian; `salt` and `K` are raw. `PAD` left-pads to 256 bytes. Layout: pyatv 0.18.0.
//!
//! `num-bigint`'s `modpow` is variable-time; the PIN is single-use and `a` is per-session.

use num_bigint::BigUint;
use num_traits::Zero;
use rand_core::CryptoRng;
use sha1::{Digest, Sha1};

/// Byte length of the 2048-bit modulus. `PAD` targets this width.
pub const MODULUS_BYTES: usize = 256;

/// The longest salt [`LegacySrpClient::process_challenge`] accepts. Observed: 16 bytes.
pub const MAX_SALT_BYTES: usize = 64;

/// RFC 5054 2048-bit group prime, big-endian hex.
const N_HEX: &str = concat!(
    "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC319294",
    "3DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310D",
    "CD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FB",
    "D5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF74",
    "7359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A",
    "436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D",
    "5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E73",
    "03CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6",
    "94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F",
    "9E4AFF73",
);

/// The SRP generator for the legacy group.
const G: u32 = 2;

/// Left-zero-pads a big-endian byte string to the modulus width.
fn pad_to(bytes: &[u8], width: usize) -> Vec<u8> {
    if bytes.len() >= width {
        return bytes.to_vec();
    }
    let mut out = vec![0u8; width - bytes.len()];
    out.extend_from_slice(bytes);
    out
}

/// Left-zero-pads to the legacy AirPlay group's [`MODULUS_BYTES`] (only the test server uses it).
#[cfg(feature = "test-server")]
fn pad(bytes: &[u8]) -> Vec<u8> {
    pad_to(bytes, MODULUS_BYTES)
}

/// SHA-1 over the concatenation of the parts.
fn hash(parts: &[&[u8]]) -> Vec<u8> {
    let mut hasher = Sha1::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().to_vec()
}

/// Strips leading zero bytes (all-zero becomes a single `0x00`); the reference concatenates
/// hashes as integers, so a digest starting with `0x00` contributes 19 bytes.
fn minimal(bytes: &[u8]) -> Vec<u8> {
    match bytes.iter().position(|b| *b != 0) {
        Some(start) => bytes[start..].to_vec(),
        None => vec![0u8],
    }
}

/// Apple's session key: `K = H(S | 00000000) | H(S | 00000001)`, 40 bytes.
fn session_key_from(s_minimal: &[u8]) -> Vec<u8> {
    let mut key = hash(&[s_minimal, &[0, 0, 0, 0]]);
    key.extend_from_slice(&hash(&[s_minimal, &[0, 0, 0, 1]]));
    key
}

fn modulus() -> BigUint {
    BigUint::parse_bytes(N_HEX.as_bytes(), 16).expect("the embedded 2048-bit prime is valid hex")
}

/// The legacy SRP-6a client: answers a `/pair-setup-pin` challenge, with no I/O. The PIN is wiped
/// on drop; `a` is a `BigUint`, whose limbs cannot be.
pub struct LegacySrpClient {
    username: Vec<u8>,
    pin: Vec<u8>,
    n: BigUint,
    g: BigUint,
    a: BigUint,
    a_pub: BigUint,
    /// Modulus width in bytes; a field so the RFC 5054 Appendix B vector (1024-bit) can reuse the
    /// code.
    width: usize,
}

/// The completed client side.
pub struct LegacySrpProof {
    /// Client public value `A`, minimal big-endian.
    pub a_pub: Vec<u8>,
    /// Client proof `M1`.
    pub m1: Vec<u8>,
    /// Expected server proof `M2`, to check against the receiver's reply.
    pub m2: Vec<u8>,
    /// Session key `K` (**40 bytes**), the input to the step-3 AES key derivation.
    pub session_key: Vec<u8>,
}

impl Drop for LegacySrpClient {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.pin);
    }
}

impl LegacySrpClient {
    /// Creates a client with a caller-supplied ephemeral secret `a` (for replayable tests).
    #[must_use]
    pub fn with_secret(username: &str, pin: &str, a_bytes: &[u8]) -> Self {
        Self::with_group(&modulus(), G, MODULUS_BYTES, username, pin, a_bytes)
    }

    /// Creates a client over an explicit SRP group, so the RFC 5054 Appendix B vector can drive it.
    #[doc(hidden)]
    #[must_use]
    pub fn with_group(
        n: &BigUint,
        generator: u32,
        width: usize,
        username: &str,
        pin: &str,
        a_bytes: &[u8],
    ) -> Self {
        let g = BigUint::from(generator);
        let a = BigUint::from_bytes_be(a_bytes);
        let a_pub = g.modpow(&a, n);
        Self {
            username: username.as_bytes().to_vec(),
            pin: pin.as_bytes().to_vec(),
            n: n.clone(),
            g,
            a,
            a_pub,
            width,
        }
    }

    /// The premaster secret `S`, minimal big-endian (for the RFC 5054 vector).
    #[doc(hidden)]
    #[must_use]
    pub fn premaster_secret(&self, salt: &[u8], b_bytes: &[u8]) -> Option<Vec<u8>> {
        self.shared_secret(salt, b_bytes).map(|s| s.to_bytes_be())
    }

    fn shared_secret(&self, salt: &[u8], b_bytes: &[u8]) -> Option<BigUint> {
        if salt.is_empty() || salt.len() > MAX_SALT_BYTES || b_bytes.len() > self.width {
            return None;
        }
        let b_pub = BigUint::from_bytes_be(b_bytes);
        if b_pub >= self.n || b_pub.is_zero() {
            return None;
        }

        let a_bytes = self.a_pub.to_bytes_be();
        let b_minimal = b_pub.to_bytes_be();
        let n_bytes = self.n.to_bytes_be();
        let g_bytes = self.g.to_bytes_be();

        let k = BigUint::from_bytes_be(&hash(&[&n_bytes, &pad_to(&g_bytes, self.width)]));

        let u = BigUint::from_bytes_be(&hash(&[
            &pad_to(&a_bytes, self.width),
            &pad_to(&b_minimal, self.width),
        ]));

        let inner = hash(&[&self.username, b":", &self.pin]);
        let x = BigUint::from_bytes_be(&hash(&[salt, &inner]));

        // S = (B - k * g^x) ^ (a + u*x) mod N, subtraction kept non-negative mod N.
        let g_x = self.g.modpow(&x, &self.n);
        let k_gx = (&k * &g_x) % &self.n;
        let base = (&b_pub + &self.n - k_gx) % &self.n;
        let exp = &self.a + &u * &x;
        Some(base.modpow(&exp, &self.n))
    }

    /// Creates a client with a fresh random ephemeral secret.
    #[must_use]
    pub fn new(username: &str, pin: &str, rng: &mut dyn CryptoRng) -> Self {
        let mut a_bytes = [0u8; 32];
        rng.fill_bytes(&mut a_bytes);
        Self::with_secret(username, pin, &a_bytes)
    }

    /// The client public value `A`, minimal big-endian.
    #[must_use]
    pub fn public_key(&self) -> Vec<u8> {
        self.a_pub.to_bytes_be()
    }

    /// Processes the receiver's salt and public value `B`. Returns `None` when `B` is zero (the
    /// abort RFC 5054 mandates), not below the modulus or longer than it, or the salt is empty or
    /// over [`MAX_SALT_BYTES`].
    #[must_use]
    pub fn process_challenge(&self, salt: &[u8], b_bytes: &[u8]) -> Option<LegacySrpProof> {
        let s = self.shared_secret(salt, b_bytes)?;
        let a_bytes = self.a_pub.to_bytes_be();
        let b_minimal = BigUint::from_bytes_be(b_bytes).to_bytes_be();
        let n_bytes = self.n.to_bytes_be();
        let g_bytes = self.g.to_bytes_be();

        let session_key = session_key_from(&s.to_bytes_be());

        // M1's inputs are minimal big-endian; the XOR's leading byte is non-zero here (asserted in
        // tests).
        let hn = hash(&[&n_bytes]);
        let hg = hash(&[&g_bytes]);
        let xor: Vec<u8> = hn.iter().zip(&hg).map(|(a, b)| a ^ b).collect();
        let hn_xor_hg = minimal(&xor);
        let h_username = minimal(&hash(&[&self.username]));
        let m1 = hash(&[
            &hn_xor_hg,
            &h_username,
            salt,
            &a_bytes,
            &b_minimal,
            &session_key,
        ]);

        let m2 = hash(&[&a_bytes, &m1, &session_key]);

        Some(LegacySrpProof {
            a_pub: a_bytes,
            m1,
            m2,
            session_key,
        })
    }
}

/// A matching SRP-6a server for self-consistency tests; not part of any shipping path. Built only
/// with the `test-server` feature.
#[cfg(feature = "test-server")]
#[doc(hidden)]
pub mod test_server {
    use super::{hash, minimal, modulus, pad, session_key_from, G};
    use num_bigint::BigUint;

    /// The verifier a receiver stores for a (username, salt, pin) triple.
    #[must_use]
    pub fn verifier(username: &str, pin: &str, salt: &[u8]) -> Vec<u8> {
        let n = modulus();
        let g = BigUint::from(G);
        let inner = hash(&[username.as_bytes(), b":", pin.as_bytes()]);
        let x = BigUint::from_bytes_be(&hash(&[salt, &inner]));
        g.modpow(&x, &n).to_bytes_be()
    }

    /// The server half of one exchange.
    pub struct Server {
        n: BigUint,
        g: BigUint,
        v: BigUint,
        b: BigUint,
        b_pub: BigUint,
        username: Vec<u8>,
        salt: Vec<u8>,
    }

    impl Server {
        /// Creates a server with a fixed ephemeral secret `b`.
        #[must_use]
        pub fn with_secret(username: &str, salt: &[u8], verifier: &[u8], b_bytes: &[u8]) -> Self {
            let n = modulus();
            let g = BigUint::from(G);
            let v = BigUint::from_bytes_be(verifier);
            let b = BigUint::from_bytes_be(b_bytes);
            let n_bytes = n.to_bytes_be();
            let g_bytes = g.to_bytes_be();
            let k = BigUint::from_bytes_be(&hash(&[&n_bytes, &pad(&g_bytes)]));
            let b_pub = ((&k * &v) + g.modpow(&b, &n)) % &n;
            Self {
                n,
                g,
                v,
                b,
                b_pub,
                username: username.as_bytes().to_vec(),
                salt: salt.to_vec(),
            }
        }

        /// The server public value `B`, minimal big-endian.
        #[must_use]
        pub fn public_key(&self) -> Vec<u8> {
            self.b_pub.to_bytes_be()
        }

        /// Verifies the client proof and returns the server proof `M2`, or `None` on mismatch.
        #[must_use]
        pub fn verify(&self, a_bytes: &[u8], m1: &[u8]) -> Option<Vec<u8>> {
            let a_pub = BigUint::from_bytes_be(a_bytes);
            let a_minimal = a_pub.to_bytes_be();
            let b_bytes = self.b_pub.to_bytes_be();
            let u = BigUint::from_bytes_be(&hash(&[&pad(&a_minimal), &pad(&b_bytes)]));
            let s = ((&a_pub * self.v.modpow(&u, &self.n)) % &self.n).modpow(&self.b, &self.n);
            let session_key = session_key_from(&s.to_bytes_be());

            let n_bytes = self.n.to_bytes_be();
            let g_bytes = self.g.to_bytes_be();
            let hn = hash(&[&n_bytes]);
            let hg = hash(&[&g_bytes]);
            let xor: Vec<u8> = hn.iter().zip(&hg).map(|(a, b)| a ^ b).collect();
            let hn_xor_hg = minimal(&xor);
            let h_username = minimal(&hash(&[&self.username]));
            let expected = hash(&[
                &hn_xor_hg,
                &h_username,
                &self.salt,
                &a_minimal,
                &b_bytes,
                &session_key,
            ]);
            if expected != m1 {
                return None;
            }

            Some(hash(&[&a_minimal, m1, &session_key]))
        }
    }
}
