//! SRP-6a as HomeKit / AirPlay use it: the client half of `/pair-setup`, plus the server half.
//!
//! RFC 5054 with padded scrambling (the RustCrypto `srp` crate's simplified proof is rejected by
//! Apple TV and HomePod at M4):
//!
//! ```text
//!   x   = H(salt | H(username | ":" | password))
//!   k   = H(PAD(N) | PAD(g))
//!   A   = g^a mod N
//!   u   = H(PAD(A) | PAD(B))
//!   S   = (B - k * g^x) ^ (a + u*x)  mod N
//!   K   = H(S)
//!   M1  = H( (H(N) XOR H(g)) | H(username) | salt | A | B | K )
//!   M2  = H( A | M1 | K )
//! ```
//!
//! `PAD` is left-zero-padding to 384 bytes; `A`, `B` and `S` are minimal big-endian elsewhere. Hash
//! is SHA-512, username `Pair-Setup`, group the RFC 5054 3072-bit group with `g = 5`.
//!
//! Timing: `num-bigint`'s `modpow` is variable-time. Acceptable: transient pairing uses a published
//! password and `a` is per-session.

use num_bigint::BigUint;
use num_traits::Zero;
use rand_core::CryptoRng;
use sha2::{Digest, Sha512};

/// Byte length of the 3072-bit modulus. `PAD` targets this width.
pub const MODULUS_BYTES: usize = 384;

/// RFC 5054 / RFC 3526 3072-bit MODP group prime (group 15), big-endian hex.
const N_HEX: &str = concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1",
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD",
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245",
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D",
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F",
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D",
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B",
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9",
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510",
    "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64",
    "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7",
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B",
    "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C",
    "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31",
    "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF",
);

/// The SRP generator for this group.
const G: u32 = 5;

/// Left-zero-pads a big-endian byte string to [`MODULUS_BYTES`]; used only for `k` and `u`.
///
/// # Panics
///
/// If `bytes` is longer than [`MODULUS_BYTES`] (inputs are reduced modulo N, so this is a bug).
fn pad(bytes: &[u8]) -> Vec<u8> {
    assert!(
        bytes.len() <= MODULUS_BYTES,
        "pad(): input is {} bytes, exceeding the {MODULUS_BYTES}-byte modulus",
        bytes.len()
    );
    if bytes.len() == MODULUS_BYTES {
        return bytes.to_vec();
    }
    let mut out = vec![0u8; MODULUS_BYTES - bytes.len()];
    out.extend_from_slice(bytes);
    out
}

/// SHA-512 over the concatenation of the parts.
fn hash(parts: &[&[u8]]) -> Vec<u8> {
    let mut hasher = Sha512::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().to_vec()
}

fn modulus() -> BigUint {
    BigUint::parse_bytes(N_HEX.as_bytes(), 16).expect("the embedded 3072-bit prime is valid hex")
}

/// The HAP SRP-6a client: everything needed to answer a `/pair-setup` challenge and check the
/// receiver's proof, with no I/O.
pub struct SrpClient {
    username: Vec<u8>,
    password: Vec<u8>,
    n: BigUint,
    g: BigUint,
    a: BigUint,
    a_pub: BigUint,
}

impl std::fmt::Debug for SrpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SrpClient").finish_non_exhaustive()
    }
}

/// The completed client side: the proof to send and the key material to keep.
pub struct SrpClientProof {
    /// Client public value `A`, minimal big-endian, to send in M3.
    pub a_pub: Vec<u8>,
    /// Client proof `M1`, to send in M3.
    pub m1: Vec<u8>,
    /// Expected server proof `M2`, to check against the receiver's M4.
    pub m2: Vec<u8>,
    /// Session key `K = H(S)` (64 bytes) — the transient shared secret.
    pub session_key: Vec<u8>,
}

impl SrpClient {
    /// Creates a client with a caller-supplied ephemeral secret `a`.
    ///
    /// `a` is injected rather than generated so a recorded exchange can be replayed exactly in a
    /// test. Production callers pass fresh random bytes ([`SrpClient::new`]).
    #[must_use]
    pub fn with_secret(username: &str, password: &str, a_bytes: &[u8]) -> Self {
        let n = modulus();
        let g = BigUint::from(G);
        let a = BigUint::from_bytes_be(a_bytes);
        let a_pub = g.modpow(&a, &n);
        Self {
            username: username.as_bytes().to_vec(),
            password: password.as_bytes().to_vec(),
            n,
            g,
            a,
            a_pub,
        }
    }

    /// Creates a client with a fresh random ephemeral secret.
    #[must_use]
    pub fn new(username: &str, password: &str, rng: &mut dyn CryptoRng) -> Self {
        let mut a_bytes = [0u8; 32];
        rng.fill_bytes(&mut a_bytes);
        Self::with_secret(username, password, &a_bytes)
    }

    /// The client public value `A`, minimal big-endian. Sent in M3.
    #[must_use]
    pub fn public_key(&self) -> Vec<u8> {
        self.a_pub.to_bytes_be()
    }

    /// Processes the receiver's salt and public value `B`, producing the proof and keys.
    ///
    /// Returns `None` when `B` is invalid: zero mod N (the SRP-6a abort condition), or longer than
    /// the modulus (which no correct server produces and which would defeat the padding invariant).
    #[must_use]
    pub fn process_challenge(&self, salt: &[u8], b_bytes: &[u8]) -> Option<SrpClientProof> {
        if b_bytes.len() > MODULUS_BYTES {
            return None; // A correct server's B is at most N bytes; reject anything longer.
        }
        let b_pub = BigUint::from_bytes_be(b_bytes);
        if (&b_pub % &self.n).is_zero() {
            return None; // Safety check from RFC 5054: reject B ≡ 0 (mod N).
        }

        let a_bytes = self.a_pub.to_bytes_be();
        let n_bytes = self.n.to_bytes_be();
        let g_bytes = self.g.to_bytes_be();

        // k = H(PAD(N) | PAD(g))
        let k = BigUint::from_bytes_be(&hash(&[&pad(&n_bytes), &pad(&g_bytes)]));

        // u = H(PAD(A) | PAD(B))
        let u = BigUint::from_bytes_be(&hash(&[&pad(&a_bytes), &pad(b_bytes)]));

        // x = H(salt | H(username | ":" | password))
        let inner = hash(&[&self.username, b":", &self.password]);
        let x = BigUint::from_bytes_be(&hash(&[salt, &inner]));

        // S = (B - k * g^x) ^ (a + u*x) mod N, with the subtraction kept non-negative mod N.
        let g_x = self.g.modpow(&x, &self.n);
        let k_gx = (&k * &g_x) % &self.n;
        let base = (&b_pub + &self.n - k_gx) % &self.n;
        let exp = &self.a + &u * &x;
        let s = base.modpow(&exp, &self.n);

        // K = H(S)
        let session_key = hash(&[&s.to_bytes_be()]);

        // M1 = H( (H(N) XOR H(g)) | H(username) | salt | A | B | K )
        let hn = hash(&[&n_bytes]);
        let hg = hash(&[&g_bytes]);
        let hn_xor_hg: Vec<u8> = hn.iter().zip(&hg).map(|(a, b)| a ^ b).collect();
        let h_username = hash(&[&self.username]);
        let m1 = hash(&[
            &hn_xor_hg,
            &h_username,
            salt,
            &a_bytes,
            b_bytes,
            &session_key,
        ]);

        // M2 = H( A | M1 | K ) — what the receiver must send back to prove it too knew the PIN.
        let m2 = hash(&[&a_bytes, &m1, &session_key]);

        Some(SrpClientProof {
            a_pub: a_bytes,
            m1,
            m2,
            session_key,
        })
    }
}

/// The HAP SRP-6a server: the receiver half of `/pair-setup` ([`crate::receiver`]).
///
/// `v = g^x`, `B = k*v + g^b`, `S = (A * v^u) ^ b`; K, M1 and M2 as the client computes them.
/// `A`, `B` and the salt are hashed as the bytes that crossed the wire, and K, M1 and M2 are full
/// 64-byte digests. Pinned against `srptools` as pyatv 0.18.0 configures it.
pub struct SrpServer {
    username: Vec<u8>,
    salt: Vec<u8>,
    n: BigUint,
    g: BigUint,
    v: BigUint,
    b: BigUint,
    b_pub: BigUint,
}

impl std::fmt::Debug for SrpServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SrpServer").finish_non_exhaustive()
    }
}

/// A client proof the server accepted: the proof to send back and the shared key.
pub struct SrpServerProof {
    /// `M2`, sent in pair-setup M4.
    pub m2: Vec<u8>,
    /// `K = H(S)` (64 bytes) — the same session key the client derives.
    pub session_key: Vec<u8>,
}

impl SrpServer {
    /// A server for `(username, password)` with a caller-chosen salt and ephemeral secret `b`
    /// (injected so a vector replays exactly; production callers draw both from a CSPRNG).
    #[must_use]
    pub fn with_secret(username: &str, password: &str, salt: &[u8], b_bytes: &[u8]) -> Self {
        let n = modulus();
        let g = BigUint::from(G);
        let inner = hash(&[username.as_bytes(), b":", password.as_bytes()]);
        let x = BigUint::from_bytes_be(&hash(&[salt, &inner]));
        let v = g.modpow(&x, &n);
        let k = BigUint::from_bytes_be(&hash(&[&pad(&n.to_bytes_be()), &pad(&g.to_bytes_be())]));
        let b = BigUint::from_bytes_be(b_bytes);
        let b_pub = (&k * &v + g.modpow(&b, &n)) % &n;
        Self {
            username: username.as_bytes().to_vec(),
            salt: salt.to_vec(),
            n,
            g,
            v,
            b,
            b_pub,
        }
    }

    /// A server with a fresh 16-byte salt and 32-byte `b` from `rng`.
    #[must_use]
    pub fn new(username: &str, password: &str, rng: &mut dyn CryptoRng) -> Self {
        let mut salt = [0u8; 16];
        rng.fill_bytes(&mut salt);
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut b);
        Self::with_secret(username, password, &salt, &b)
    }

    /// The salt, sent in M2.
    #[must_use]
    pub fn salt(&self) -> &[u8] {
        &self.salt
    }

    /// The server public value `B`, minimal big-endian, sent in M2.
    #[must_use]
    pub fn public_key(&self) -> Vec<u8> {
        self.b_pub.to_bytes_be()
    }

    /// Checks the client's `A` and proof `M1` (pair-setup M3). `None` when `A` is invalid (zero
    /// mod N, or longer than the modulus) or the proof does not match — which is what a wrong PIN
    /// looks like from here.
    #[must_use]
    pub fn verify_client(&self, a_bytes: &[u8], client_m1: &[u8]) -> Option<SrpServerProof> {
        if a_bytes.len() > MODULUS_BYTES || a_bytes.is_empty() {
            return None;
        }
        let a_pub = BigUint::from_bytes_be(a_bytes);
        if (&a_pub % &self.n).is_zero() {
            return None; // RFC 5054's abort condition, from the server's side.
        }
        let b_bytes = self.b_pub.to_bytes_be();
        let u = BigUint::from_bytes_be(&hash(&[&pad(a_bytes), &pad(&b_bytes)]));
        let s = ((&a_pub * self.v.modpow(&u, &self.n)) % &self.n).modpow(&self.b, &self.n);
        let session_key = hash(&[&s.to_bytes_be()]);

        let hn = hash(&[&self.n.to_bytes_be()]);
        let hg = hash(&[&self.g.to_bytes_be()]);
        let hn_xor_hg: Vec<u8> = hn.iter().zip(&hg).map(|(x, y)| x ^ y).collect();
        let h_username = hash(&[&self.username]);
        let m1 = hash(&[
            &hn_xor_hg,
            &h_username,
            &self.salt,
            a_bytes,
            &b_bytes,
            &session_key,
        ]);
        if !crate::pairing::constant_time_eq(&m1, client_m1) {
            return None;
        }
        let m2 = hash(&[a_bytes, &m1, &session_key]);
        Some(SrpServerProof { m2, session_key })
    }
}

/// A matching server for integration tests only; `#[cfg(test)]` items are invisible to them, so
/// it is built only with the `test-server` feature. The receiver's server is [`SrpServer`].
#[cfg(feature = "test-server")]
#[doc(hidden)]
pub mod test_server {
    use super::{hash, modulus, pad, G};
    use num_bigint::BigUint;
    use sha2::{Digest, Sha512};

    /// The verifier a server stores for a (username, salt, password) triple.
    #[must_use]
    pub fn verifier(username: &str, password: &str, salt: &[u8]) -> Vec<u8> {
        let n = modulus();
        let g = BigUint::from(G);
        let inner = hash(&[username.as_bytes(), b":", password.as_bytes()]);
        let x = BigUint::from_bytes_be(&hash(&[salt, &inner]));
        g.modpow(&x, &n).to_bytes_be()
    }

    /// One server exchange: given the stored verifier and the client's A, returns B and the proofs.
    #[must_use]
    pub fn respond(
        verifier: &[u8],
        a_bytes: &[u8],
        b_secret: &[u8],
        salt: &[u8],
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        let n = modulus();
        let g = BigUint::from(G);
        let v = BigUint::from_bytes_be(verifier);
        let a_pub = BigUint::from_bytes_be(a_bytes);
        let b = BigUint::from_bytes_be(b_secret);

        let n_bytes = n.to_bytes_be();
        let g_bytes = g.to_bytes_be();
        let k = BigUint::from_bytes_be(&hash(&[&pad(&n_bytes), &pad(&g_bytes)]));

        // B = (k*v + g^b) mod N
        let b_pub = (&k * &v + g.modpow(&b, &n)) % &n;
        let b_pub_bytes = b_pub.to_bytes_be();

        let u = BigUint::from_bytes_be(&hash(&[&pad(a_bytes), &pad(&b_pub_bytes)]));

        // S = (A * v^u) ^ b mod N
        let s = (&a_pub * v.modpow(&u, &n) % &n).modpow(&b, &n);
        let session_key = hash(&[&s.to_bytes_be()]);

        let hn = hash(&[&n_bytes]);
        let hg = hash(&[&g_bytes]);
        let hn_xor_hg: Vec<u8> = hn.iter().zip(&hg).map(|(x, y)| x ^ y).collect();
        let h_username = {
            let mut hasher = Sha512::new();
            hasher.update(b"Pair-Setup");
            hasher.finalize().to_vec()
        };
        let m1 = hash(&[
            &hn_xor_hg,
            &h_username,
            salt,
            a_bytes,
            &b_pub_bytes,
            &session_key,
        ]);
        let m2 = hash(&[a_bytes, &m1, &session_key]);

        (b_pub_bytes, m1, m2, session_key)
    }
}
