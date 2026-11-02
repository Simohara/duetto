//! Legacy AirPlay PIN pairing, the flow current Apple TVs still accept where HAP transient
//! pair-setup is rejected. Sans-io: each step takes the receiver's bytes and returns the next body.
//!
//! ```text
//!   POST /pair-pin-start                          -> 200, receiver shows four digits
//!   POST /pair-setup-pin  {method:"pin", user:ID} -> 200, {salt: 16B, pk: 256B}
//!   POST /pair-setup-pin  {pk: A, proof: M1}      -> 200, {proof: M2}
//!   POST /pair-setup-pin  {epk, authTag}          -> 200, pairing stored
//! ```
//!
//! The result is an Ed25519 identity the receiver stores; later connections prove it with
//! [`PairVerify`]. SRP details (SHA-1, 2048-bit group, 40-byte `K`) are in [`srp`].

pub mod srp;

use std::collections::BTreeMap;

use aes::cipher::{KeyIvInit, StreamCipher};
use aes_gcm::aead::consts::U16;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{AesGcm, KeyInit};
use ed25519_dalek::{Signer, SigningKey};
use plist::Value;
use rand_core::CryptoRng;
use sha2::{Digest, Sha512};
use zeroize::{Zeroize, Zeroizing};

use self::srp::LegacySrpClient;
use crate::error::{AirPlayError, Result};

type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;

/// AES-128-GCM with a **16-byte** nonce (the protocol feeds a 16-byte IV to GCM as-is; `Aes128Gcm`
/// would panic).
type Aes128Gcm16 = AesGcm<aes::Aes128, U16>;

/// Endpoint that makes the receiver display a PIN (shared with the HAP flow).
pub use crate::pairing::constants::PIN_START_PATH;

/// Endpoint carrying the three-step SRP exchange.
pub const PAIR_SETUP_PIN_PATH: &str = "/pair-setup-pin";

/// Endpoint that proves possession of a stored pairing.
pub const PAIR_VERIFY_PATH: &str = "/pair-verify";

/// Content type of every legacy pairing body that is a plist.
pub const PLIST_CONTENT_TYPE: &str = "application/x-apple-binary-plist";

/// Content type of the two raw `/pair-verify` bodies.
pub const OCTET_CONTENT_TYPE: &str = "application/octet-stream";

/// Literal string prefixes hashed with the shared secret; not real HKDF.
mod labels {
    /// AES key for sealing our public key in pair-setup step 3.
    pub const SETUP_AES_KEY: &[u8] = b"Pair-Setup-AES-Key";
    /// AES IV for the same (its last byte is incremented before use).
    pub const SETUP_AES_IV: &[u8] = b"Pair-Setup-AES-IV";
    /// AES key for the pair-verify signature stream.
    pub const VERIFY_AES_KEY: &[u8] = b"Pair-Verify-AES-Key";
    /// AES IV for the same.
    pub const VERIFY_AES_IV: &[u8] = b"Pair-Verify-AES-IV";
}

/// A stored legacy pairing: the identity a receiver agreed to trust.
///
/// Persist protected. Losing it only means re-pairing with a new PIN. Equality compares the seed
/// in constant time. The seed is wiped on drop, so a field cannot be moved out of it (clone the
/// identifier instead); it also implements [`zeroize::Zeroize`].
#[derive(Clone)]
pub struct LegacyCredentials {
    /// Client identifier presented as the SRP username. A UUID, stable per install.
    pub identifier: String,
    /// Ed25519 seed. The public half is what the receiver stored.
    pub seed: [u8; 32],
}

impl std::fmt::Debug for LegacyCredentials {
    /// Deliberately opaque: the seed is the identity a receiver has agreed to trust.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LegacyCredentials")
            .field("identifier", &self.identifier)
            .field("seed", &"<redacted>")
            .finish()
    }
}

impl PartialEq for LegacyCredentials {
    fn eq(&self, other: &Self) -> bool {
        let seeds = crate::pairing::constant_time_eq(&self.seed, &other.seed);
        seeds & (self.identifier == other.identifier)
    }
}

impl Eq for LegacyCredentials {}

impl Zeroize for LegacyCredentials {
    fn zeroize(&mut self) {
        self.identifier.zeroize();
        self.seed.zeroize();
    }
}

impl Drop for LegacyCredentials {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

impl LegacyCredentials {
    /// Generates a fresh identity.
    pub fn generate(rng: &mut dyn CryptoRng) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        Self {
            identifier: random_identifier(rng),
            seed,
        }
    }

    /// Serializes as `identifier:seed-hex` (the pyatv shape).
    #[must_use]
    pub fn to_storage_string(&self) -> String {
        format!("{}:{}", self.identifier, hex::encode(self.seed))
    }

    /// Parses [`Self::to_storage_string`].
    pub fn parse(text: &str) -> Result<Self> {
        let (identifier, seed_hex) = text.split_once(':').ok_or_else(|| {
            AirPlayError::Credentials("credentials are not `identifier:seed`".to_owned())
        })?;
        let bytes = hex::decode(seed_hex)
            .map_err(|_| AirPlayError::Credentials("credential seed is not hex".to_owned()))?;
        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| AirPlayError::Credentials("credential seed is not 32 bytes".to_owned()))?;
        Ok(Self {
            identifier: identifier.to_owned(),
            seed,
        })
    }

    /// The Ed25519 signing key.
    #[must_use]
    pub fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.seed)
    }
}

/// What the caller should do next in a legacy exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LegacyStep {
    /// POST this body to the endpoint and feed the reply back in.
    Send(Vec<u8>),
    /// The exchange finished.
    Done,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SetupState {
    Start,
    AwaitingChallenge,
    AwaitingProof,
    AwaitingAck,
    Finished,
    Failed,
}

/// The `/pair-setup-pin` state machine. The PIN is supplied up front; the caller must POST
/// [`PIN_START_PATH`] first so the receiver displays it.
pub struct PairSetupPin {
    credentials: LegacyCredentials,
    pin: String,
    state: SetupState,
    client_secret: [u8; 32],
    session_key: Option<Vec<u8>>,
    expected_m2: Option<Vec<u8>>,
}

impl Drop for PairSetupPin {
    fn drop(&mut self) {
        self.pin.zeroize();
        self.client_secret.zeroize();
        if let Some(ref mut k) = self.session_key {
            k.zeroize();
        }
    }
}

impl PairSetupPin {
    /// Creates a run for a PIN the user read off the receiver.
    pub fn new(
        credentials: LegacyCredentials,
        pin: impl Into<String>,
        rng: &mut dyn CryptoRng,
    ) -> Self {
        let mut client_secret = [0u8; 32];
        rng.fill_bytes(&mut client_secret);
        Self {
            credentials,
            pin: pin.into(),
            state: SetupState::Start,
            client_secret,
            session_key: None,
            expected_m2: None,
        }
    }

    /// The credentials this run will produce.
    #[must_use]
    pub fn credentials(&self) -> &LegacyCredentials {
        &self.credentials
    }

    /// Step 1 body: `{method: "pin", user: <identifier>}`.
    pub fn start(&mut self) -> Result<Vec<u8>> {
        if self.state != SetupState::Start {
            return Err(AirPlayError::InvalidState(
                "legacy pair-setup has already started".to_owned(),
            ));
        }

        let mut dict = plist::Dictionary::new();
        dict.insert("method".to_owned(), Value::String("pin".to_owned()));
        dict.insert(
            "user".to_owned(),
            Value::String(self.credentials.identifier.clone()),
        );
        self.state = SetupState::AwaitingChallenge;
        encode_plist(&Value::Dictionary(dict))
    }

    /// Feeds a reply body in and returns what to send next.
    ///
    /// Only the body is seen, so the caller must check each reply's HTTP status first and stop on
    /// anything but 2xx (`ControlChannel::legacy_pair_setup` does). In particular the step-3 reply
    /// is not read at all: [`LegacyStep::Done`] means the receiver answered step 3, and only its
    /// status says whether it stored the pairing.
    pub fn handle(&mut self, body: &[u8]) -> Result<LegacyStep> {
        match self.state {
            SetupState::AwaitingChallenge => self.handle_challenge(body),
            SetupState::AwaitingProof => self.handle_proof(body),
            SetupState::AwaitingAck => {
                self.state = SetupState::Finished;
                Ok(LegacyStep::Done)
            }
            SetupState::Start => Err(AirPlayError::InvalidState(
                "legacy pair-setup has not started".to_owned(),
            )),
            SetupState::Finished | SetupState::Failed => Err(AirPlayError::InvalidState(
                "legacy pair-setup is already over".to_owned(),
            )),
        }
    }

    /// Step 1 reply (`salt`, `pk`) in, step 2 body (`pk`, `proof`) out.
    fn handle_challenge(&mut self, body: &[u8]) -> Result<LegacyStep> {
        let dict = decode_dictionary(body)?;
        let salt = take_data(&dict, "salt")?;
        let server_public = take_data(&dict, "pk")?;

        let client = LegacySrpClient::with_secret(
            &self.credentials.identifier,
            &self.pin,
            &self.client_secret,
        );
        let proof = client
            .process_challenge(&salt, &server_public)
            .ok_or_else(|| {
                self.state = SetupState::Failed;
                AirPlayError::Protocol(
                    "receiver sent an invalid SRP challenge (B out of range, or a bad salt)"
                        .to_owned(),
                )
            })?;

        let mut next = plist::Dictionary::new();
        next.insert("pk".to_owned(), Value::Data(proof.a_pub.clone()));
        next.insert("proof".to_owned(), Value::Data(proof.m1.clone()));

        self.expected_m2 = Some(proof.m2);
        self.session_key = Some(proof.session_key);
        self.state = SetupState::AwaitingProof;
        Ok(LegacyStep::Send(encode_plist(&Value::Dictionary(next))?))
    }

    /// Step 2 reply (`proof`) in, step 3 body (`epk`, `authTag`) out.
    fn handle_proof(&mut self, body: &[u8]) -> Result<LegacyStep> {
        let dict = decode_dictionary(body)?;
        let server_proof = take_data(&dict, "proof")?;
        let expected = self
            .expected_m2
            .as_ref()
            .ok_or_else(|| AirPlayError::InvalidState("no expected proof recorded".to_owned()))?;

        // Without this check anything answering on port 7000 could hand us a key.
        if !crate::pairing::constant_time_eq(&server_proof, expected) {
            self.state = SetupState::Failed;
            return Err(AirPlayError::Protocol(
                "the receiver's proof did not verify; it does not know the PIN you typed"
                    .to_owned(),
            ));
        }

        let session_key = self
            .session_key
            .as_ref()
            .ok_or_else(|| AirPlayError::InvalidState("no session key recorded".to_owned()))?;
        let public = self.credentials.signing_key().verifying_key().to_bytes();
        let (encrypted, tag) = seal_setup_key(session_key, &public)?;

        let mut next = plist::Dictionary::new();
        next.insert("epk".to_owned(), Value::Data(encrypted));
        next.insert("authTag".to_owned(), Value::Data(tag));

        self.state = SetupState::AwaitingAck;
        Ok(LegacyStep::Send(encode_plist(&Value::Dictionary(next))?))
    }
}

/// AES-128-GCM over our Ed25519 public key, keyed from the SRP session key. The 16-byte IV has
/// its last byte incremented.
fn seal_setup_key(session_key: &[u8], public: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let key = Zeroizing::new(derive16(labels::SETUP_AES_KEY, session_key));
    let mut iv = Zeroizing::new(derive16(labels::SETUP_AES_IV, session_key));
    let last = iv.len() - 1;
    iv[last] = iv[last].wrapping_add(1);

    let cipher = Aes128Gcm16::new(&(*key).into());
    let sealed = cipher
        .encrypt(
            &(*iv).into(),
            Payload {
                msg: public,
                aad: &[],
            },
        )
        .map_err(|_| AirPlayError::Protocol("pair-setup step 3 encryption failed".to_owned()))?;

    // RustCrypto appends the 16-byte tag; the protocol carries it as a separate plist field.
    let split = sealed.len() - 16;
    Ok((sealed[..split].to_vec(), sealed[split..].to_vec()))
}

/// The `/pair-verify` state machine: proves possession of a stored [`LegacyCredentials`]. The
/// receiver's encrypted signature is not checked, but must still pass through the cipher because
/// the keystream continues into our reply.
pub struct PairVerify {
    signing_key: SigningKey,
    ephemeral_secret: [u8; 32],
    ephemeral_public: [u8; 32],
    started: bool,
}

impl Drop for PairVerify {
    fn drop(&mut self) {
        self.ephemeral_secret.zeroize();
    }
}

impl PairVerify {
    /// Creates a verify run for stored credentials.
    pub fn new(credentials: &LegacyCredentials, rng: &mut dyn CryptoRng) -> Self {
        let mut ephemeral_secret = [0u8; 32];
        rng.fill_bytes(&mut ephemeral_secret);
        Self::with_secret(credentials, ephemeral_secret)
    }

    /// Creates a verify run with a caller-supplied ephemeral secret, for replayable tests.
    #[must_use]
    pub fn with_secret(credentials: &LegacyCredentials, ephemeral_secret: [u8; 32]) -> Self {
        let secret = x25519_dalek::StaticSecret::from(ephemeral_secret);
        let ephemeral_public = x25519_dalek::PublicKey::from(&secret).to_bytes();
        Self {
            signing_key: credentials.signing_key(),
            ephemeral_secret,
            ephemeral_public,
            started: false,
        }
    }

    /// First body: `01 00 00 00 | X25519 public | Ed25519 public` (68 bytes).
    pub fn start(&mut self) -> Result<Vec<u8>> {
        if self.started {
            return Err(AirPlayError::InvalidState(
                "legacy pair-verify has already started".to_owned(),
            ));
        }
        self.started = true;

        let mut body = Vec::with_capacity(68);
        body.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
        body.extend_from_slice(&self.ephemeral_public);
        body.extend_from_slice(&self.signing_key.verifying_key().to_bytes());
        Ok(body)
    }

    /// Receiver's 96-byte reply in, our 68-byte signed answer out.
    pub fn handle(&mut self, reply: &[u8]) -> Result<Vec<u8>> {
        if !self.started {
            return Err(AirPlayError::InvalidState(
                "legacy pair-verify has not started".to_owned(),
            ));
        }
        if reply.len() < 96 {
            return Err(AirPlayError::Protocol(format!(
                "pair-verify reply is {} bytes, expected 96",
                reply.len()
            )));
        }

        let mut atv_public = [0u8; 32];
        atv_public.copy_from_slice(&reply[..32]);

        let secret = x25519_dalek::StaticSecret::from(self.ephemeral_secret);
        let shared = Zeroizing::new(
            secret
                .diffie_hellman(&x25519_dalek::PublicKey::from(atv_public))
                .to_bytes(),
        );

        let key = Zeroizing::new(derive16(labels::VERIFY_AES_KEY, &*shared));
        let iv = Zeroizing::new(derive16(labels::VERIFY_AES_IV, &*shared));
        let mut cipher = Aes128Ctr::new(&(*key).into(), &(*iv).into());

        // SECURITY: the receiver's signature is decrypted and dropped (no receiver public key to
        // check it against), so a MITM could substitute its own ephemeral key.
        let mut discard = reply[32..96].to_vec();
        cipher.apply_keystream(&mut discard);

        let mut signed = Vec::with_capacity(64);
        signed.extend_from_slice(&self.ephemeral_public);
        signed.extend_from_slice(&atv_public);
        let mut signature = self.signing_key.sign(&signed).to_bytes().to_vec();
        cipher.apply_keystream(&mut signature);

        let mut body = Vec::with_capacity(68);
        body.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        body.extend_from_slice(&signature);
        Ok(body)
    }
}

/// `SHA-512(label | secret)[..16]` — the legacy key/IV derivation.
fn derive16(label: &[u8], secret: &[u8]) -> [u8; 16] {
    let mut hasher = Sha512::new();
    hasher.update(label);
    hasher.update(secret);
    let mut out = [0; 16];
    out.copy_from_slice(&hasher.finalize()[..16]);
    out
}

/// Client identifier: eight random bytes as sixteen uppercase hex characters (pyatv's shape).
fn random_identifier(rng: &mut dyn CryptoRng) -> String {
    let mut bytes = [0u8; 8];
    rng.fill_bytes(&mut bytes);
    hex::encode_upper(bytes)
}

fn encode_plist(value: &Value) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    plist::to_writer_binary(&mut out, value)
        .map_err(|e| AirPlayError::Protocol(format!("could not encode plist: {e}")))?;
    Ok(out)
}

fn decode_dictionary(body: &[u8]) -> Result<BTreeMap<String, Value>> {
    let value = crate::safe_plist::parse(body, "reply is not a plist")?;
    let dict = value
        .into_dictionary()
        .ok_or_else(|| AirPlayError::Protocol("reply plist is not a dictionary".to_owned()))?;
    Ok(dict.into_iter().collect())
}

fn take_data(dict: &BTreeMap<String, Value>, key: &str) -> Result<Vec<u8>> {
    dict.get(key)
        .and_then(|value| value.as_data())
        .map(<[u8]>::to_vec)
        .ok_or_else(|| AirPlayError::Protocol(format!("reply has no `{key}` data field")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_credentials_round_trip() {
        let cred = LegacyCredentials {
            identifier: "test-id".to_owned(),
            seed: [0xAB; 32],
        };
        let stored = cred.to_storage_string();
        let parsed = LegacyCredentials::parse(&stored).unwrap();
        assert_eq!(parsed.identifier, "test-id");
        assert_eq!(parsed.seed, [0xAB; 32]);
    }

    #[test]
    fn legacy_credentials_missing_colon_is_credentials_error() {
        let err = LegacyCredentials::parse("no-colon-here").unwrap_err();
        assert!(
            matches!(err, AirPlayError::Credentials(_)),
            "expected Credentials, got {err:?}"
        );
    }

    #[test]
    fn legacy_credentials_bad_hex_is_credentials_error() {
        let err = LegacyCredentials::parse("id:not-hex!!").unwrap_err();
        assert!(matches!(err, AirPlayError::Credentials(_)));
    }

    #[test]
    fn legacy_credentials_wrong_length_is_credentials_error() {
        let err = LegacyCredentials::parse("id:aabb").unwrap_err();
        assert!(matches!(err, AirPlayError::Credentials(_)));
    }
}
