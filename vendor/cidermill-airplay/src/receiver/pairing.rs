//! HAP pairing, receiver side: pair-setup (transient and PIN) and pair-verify as the accessory
//! answers them, mirroring [`crate::pairing`] with the same constants and primitives.
//!
//! - pair-setup M1/M2: salt and `B` from [`SrpServer`]; the PIN is [`constants::TRANSIENT_PIN`] for
//!   [`flags::TRANSIENT`], else the one from [`super::pin::PinGate`]. A refusing gate answers M2
//!   with HAP's error.
//! - M3/M4: proof checked; a wrong PIN is counted and replaced ([`PairingOutcome::Failed`]). M5/M6:
//!   the controller's key is handed to the host to store.
//! - pair-verify M1-M4: an unknown controller gets `kTLVError_Authentication` in M4, not keys.
//!
//! Session keys come out in the receiver's orientation ([`receiver_control_keys`],
//! [`receiver_event_keys`]). Sans-io: TLV8 in and out, the caller's RNG, the host's
//! [`super::ControllerStore`].

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::CryptoRng;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};

use std::net::IpAddr;
use std::sync::Arc;

use super::pin::{PinAfterFailure, PinClaim, PinGate, PinRefusal, PinStart, UNKNOWN_SOURCE};
use crate::error::{AirPlayError, Result};
use crate::pairing::{constants, hkdf_key, open, seal, DirectionalKeys, SessionKeys};
use crate::srp6a::SrpServer;
use crate::tlv8::{tag, Tlv8};
use crate::{flags, PairingError};

use super::pin::{ERROR_AUTHENTICATION, ERROR_BUSY};

/// `kTLVError_Unavailable`.
const ERROR_UNAVAILABLE: u8 = 0x06;

/// The control-channel keys in the receiver's orientation: `write_key` is the sender's read key
/// (`Control-Read-Encryption-Key`) and `read_key` its write key.
pub fn receiver_control_keys(shared_secret: &[u8]) -> Result<SessionKeys> {
    Ok(SessionKeys {
        shared_secret: shared_secret.to_vec(),
        write_key: hkdf_key(
            shared_secret,
            constants::CONTROL_SALT,
            constants::CONTROL_READ_INFO,
        )?,
        read_key: hkdf_key(
            shared_secret,
            constants::CONTROL_SALT,
            constants::CONTROL_WRITE_INFO,
        )?,
    })
}

/// The event channel's keys for the receiver: [`SessionKeys::event_keys`] reversed.
///
/// # Errors
///
/// HKDF refusing the expansion (it does not for these lengths).
pub fn receiver_event_keys(keys: &SessionKeys) -> Result<DirectionalKeys> {
    Ok(keys.event_keys()?.reversed())
}

/// What a pairing request resolved to.
#[derive(Debug)]
#[non_exhaustive]
pub enum PairingOutcome {
    /// Answer with this TLV8 and keep going.
    Reply(Tlv8),
    /// Answer with this TLV8, then switch the connection to encrypted framing with these keys
    /// (receiver orientation). `controller` is the verified controller id, `None` for transient.
    Encrypt {
        /// The reply (pair-setup M4 or pair-verify M4).
        reply: Tlv8,
        /// The keys, receiver orientation.
        keys: Box<SessionKeys>,
        /// Who, when known.
        controller: Option<Vec<u8>>,
    },
    /// Answer with this TLV8; a PIN pair-setup stored `controller` with its long-term key.
    Paired {
        /// M6.
        reply: Tlv8,
        /// The controller's pairing identifier.
        controller: Vec<u8>,
        /// Its Ed25519 public key.
        controller_key: [u8; 32],
    },
    /// A PIN setup's M1 arrived with no PIN valid: one was drawn (show it) and M2 carries
    /// `kTLVError_Authentication`. Nothing is counted.
    ShowPin {
        /// M2, to send once the PIN is on screen.
        reply: Tlv8,
        /// The digits.
        pin: String,
    },
    /// A PIN attempt failed (answer with this error TLV8): a new PIN to show, or none because
    /// pairing is locked.
    Failed {
        /// M4 or M6, carrying `kTLVError_Authentication`.
        reply: Tlv8,
        /// What happened to the PIN.
        pin: PinAfterFailure,
    },
}

fn error_reply(state: u8, code: u8) -> Tlv8 {
    let mut reply = Tlv8::new();
    reply.push_byte(tag::STATE, state);
    reply.push_byte(tag::ERROR, code);
    reply
}

/// HAP's answer to an attempt the gate refused: the error, plus `kTLVType_RetryDelay` for a
/// backoff.
#[must_use]
pub fn refusal_reply(state: u8, refusal: PinRefusal) -> Tlv8 {
    let mut reply = error_reply(state, refusal.code());
    if let Some(seconds) = refusal.retry_delay_seconds() {
        reply.push_u32_compact(tag::RETRY_DELAY, u32::from(seconds));
    }
    reply
}

fn state_of(message: &Tlv8) -> Result<u8> {
    message
        .get_byte(tag::STATE)
        .ok_or_else(|| AirPlayError::Protocol("pairing message carries no state".to_owned()))
}

/// Our long-term pairing identity: the identifier the controller files us under and our Ed25519
/// key.
#[derive(Clone)]
pub struct AccessoryIdentity {
    /// Pairing identifier (the advertised `pi`).
    pub identifier: Vec<u8>,
    /// Long-term signing key (its public half is the advertised `pk`).
    pub signing_key: SigningKey,
}

impl std::fmt::Debug for AccessoryIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessoryIdentity")
            .field("identifier", &String::from_utf8_lossy(&self.identifier))
            .finish_non_exhaustive()
    }
}

/// The receiver's pair-setup state machine, one per connection; the PIN comes from the shared
/// [`PinGate`].
pub struct PairSetupServer {
    identity: AccessoryIdentity,
    allow_transient: bool,
    fixed_pin: Option<String>,
    gate: Arc<PinGate>,
    owner: u64,
    /// Where the PIN limits count this connection's failures.
    source: IpAddr,
    srp: Option<SrpServer>,
    /// The PIN this setup's SRP verifier was built from (a PIN setup only).
    pin: Option<String>,
    transient: bool,
    session_key: Option<Vec<u8>>,
    state: u8,
}

impl std::fmt::Debug for PairSetupServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairSetupServer")
            .field("state", &self.state)
            .field("transient", &self.transient)
            .finish_non_exhaustive()
    }
}

impl PairSetupServer {
    /// A server with a gate of its own. `fixed_pin` pins the PIN (tests); `None` draws
    /// [`super::pin::PIN_DIGITS`] random digits.
    #[must_use]
    pub fn new(
        identity: AccessoryIdentity,
        allow_transient: bool,
        fixed_pin: Option<String>,
    ) -> Self {
        Self::with_gate(
            identity,
            allow_transient,
            fixed_pin,
            Arc::new(PinGate::new()),
        )
    }

    /// A server sharing the receiver's gate, as [`super::ReceiverConnection`] builds.
    #[must_use]
    pub fn with_gate(
        identity: AccessoryIdentity,
        allow_transient: bool,
        fixed_pin: Option<String>,
        gate: Arc<PinGate>,
    ) -> Self {
        let owner = gate.register();
        Self {
            identity,
            allow_transient,
            fixed_pin,
            gate,
            owner,
            source: UNKNOWN_SOURCE,
            srp: None,
            pin: None,
            transient: false,
            session_key: None,
            state: 0,
        }
    }

    /// Names the peer this connection's PIN attempts are counted against (default
    /// [`UNKNOWN_SOURCE`]).
    pub fn set_source(&mut self, source: IpAddr) {
        self.source = source;
    }

    /// `/pair-pin-start`: make sure a PIN is valid, and whether to show it.
    pub fn start_pin(&mut self, rng: &mut dyn CryptoRng) -> PinStart {
        self.gate
            .pin_start_from(self.source, self.fixed_pin.as_deref(), rng)
    }

    fn reset(&mut self) {
        self.srp = None;
        self.pin = None;
        self.session_key = None;
        self.state = 0;
    }

    /// Counts a failed PIN attempt and says what it did to the PIN.
    fn failed(&mut self, state: u8, rng: &mut dyn CryptoRng) -> PairingOutcome {
        let used = self.pin.clone().unwrap_or_default();
        self.reset();
        let pin = self
            .gate
            .fail(self.owner, &used, self.fixed_pin.as_deref(), rng);
        PairingOutcome::Failed {
            reply: error_reply(state, ERROR_AUTHENTICATION),
            pin,
        }
    }

    /// Feeds one `/pair-setup` body.
    pub fn handle(&mut self, message: &Tlv8, rng: &mut dyn CryptoRng) -> Result<PairingOutcome> {
        match state_of(message)? {
            1 => self.m1(message, rng),
            3 => self.m3(message, rng),
            5 => self.m5(message, rng),
            other => Err(AirPlayError::Protocol(format!(
                "pair-setup: unexpected state {other} from a controller"
            ))),
        }
    }

    fn m1(&mut self, message: &Tlv8, rng: &mut dyn CryptoRng) -> Result<PairingOutcome> {
        let transient = message
            .get_u32(tag::FLAGS)
            .is_some_and(|f| f & flags::TRANSIENT != 0);
        if transient && !self.allow_transient {
            return Ok(PairingOutcome::Reply(error_reply(2, ERROR_UNAVAILABLE)));
        }
        self.reset();
        self.transient = transient;
        let pin = if transient {
            // Transient: nothing to guess; release any earlier PIN hold.
            self.gate.release(self.owner);
            constants::TRANSIENT_PIN.to_owned()
        } else {
            match self.gate.begin_setup_from(
                self.owner,
                self.source,
                self.fixed_pin.as_deref(),
                rng,
            ) {
                PinClaim::Claimed(pin) => {
                    self.pin = Some(pin.clone());
                    pin
                }
                // A PIN was just drawn; nothing is counted.
                PinClaim::Drawn(pin) => {
                    return Ok(PairingOutcome::ShowPin {
                        reply: error_reply(2, ERROR_AUTHENTICATION),
                        pin,
                    })
                }
                PinClaim::Refused(refusal) => {
                    return Ok(PairingOutcome::Reply(refusal_reply(2, refusal)))
                }
            }
        };
        let server = SrpServer::new(constants::SRP_USERNAME, &pin, &mut &mut *rng);
        let mut reply = Tlv8::new();
        reply.push_byte(tag::STATE, 2);
        reply.push(tag::SALT, server.salt().to_vec());
        reply.push(tag::PUBLIC_KEY, server.public_key());
        self.srp = Some(server);
        self.state = 2;
        Ok(PairingOutcome::Reply(reply))
    }

    fn m3(&mut self, message: &Tlv8, rng: &mut dyn CryptoRng) -> Result<PairingOutcome> {
        let (Some(server), 2) = (self.srp.as_ref(), self.state) else {
            return Err(AirPlayError::InvalidState(
                "pair-setup M3 before M1".to_owned(),
            ));
        };
        if !self.transient && !self.gate.holds(self.owner) {
            // Past the gate's setup timeout another setup may have taken the gate.
            self.reset();
            return Ok(PairingOutcome::Reply(error_reply(4, ERROR_BUSY)));
        }
        let a_pub = message
            .get(tag::PUBLIC_KEY)
            .ok_or_else(|| AirPlayError::Protocol("pair-setup M3 has no public key".to_owned()))?;
        let proof = message
            .get(tag::PROOF)
            .ok_or_else(|| AirPlayError::Protocol("pair-setup M3 has no proof".to_owned()))?;
        let Some(verified) = server.verify_client(a_pub, proof) else {
            // A wrong PIN: HAP's error, and a new PIN for a PIN setup.
            if self.transient {
                self.reset();
                return Ok(PairingOutcome::Reply(error_reply(4, ERROR_AUTHENTICATION)));
            }
            return Ok(self.failed(4, rng));
        };
        let mut reply = Tlv8::new();
        reply.push_byte(tag::STATE, 4);
        reply.push(tag::PROOF, verified.m2);
        if self.transient {
            self.reset();
            return Ok(PairingOutcome::Encrypt {
                reply,
                keys: Box::new(receiver_control_keys(&verified.session_key)?),
                controller: None,
            });
        }
        self.session_key = Some(verified.session_key);
        self.state = 4;
        Ok(PairingOutcome::Reply(reply))
    }

    fn m5(&mut self, message: &Tlv8, rng: &mut dyn CryptoRng) -> Result<PairingOutcome> {
        let (Some(session_key), 4) = (self.session_key.clone(), self.state) else {
            return Err(AirPlayError::InvalidState(
                "pair-setup M5 before M3".to_owned(),
            ));
        };
        let encrypt_key = hkdf_key(
            &session_key,
            constants::SETUP_ENCRYPT_SALT,
            constants::SETUP_ENCRYPT_INFO,
        )?;
        let sealed = message.get(tag::ENCRYPTED_DATA).ok_or_else(|| {
            AirPlayError::Protocol("pair-setup M5 has no encrypted data".to_owned())
        })?;
        let Ok(opened) = open(&encrypt_key, constants::NONCE_SETUP_M5, sealed) else {
            return Ok(self.failed(6, rng));
        };
        let inner = Tlv8::decode(&opened)?;
        let controller = inner
            .get(tag::IDENTIFIER)
            .ok_or_else(|| AirPlayError::Protocol("pair-setup M5 has no identifier".to_owned()))?
            .to_vec();
        let controller_key: [u8; 32] = inner
            .get(tag::PUBLIC_KEY)
            .and_then(|k| k.try_into().ok())
            .ok_or_else(|| {
            AirPlayError::Protocol("pair-setup M5 key is not 32 bytes".to_owned())
        })?;
        let signature = inner
            .get(tag::SIGNATURE)
            .ok_or_else(|| AirPlayError::Protocol("pair-setup M5 has no signature".to_owned()))?;
        let controller_x = hkdf_key(
            &session_key,
            constants::CONTROLLER_SIGN_SALT,
            constants::CONTROLLER_SIGN_INFO,
        )?;
        let mut signed = Vec::with_capacity(64 + controller.len());
        signed.extend_from_slice(&controller_x);
        signed.extend_from_slice(&controller);
        signed.extend_from_slice(&controller_key);
        if verify(&controller_key, &signed, signature).is_err() {
            return Ok(self.failed(6, rng));
        }

        let accessory_x = hkdf_key(
            &session_key,
            constants::ACCESSORY_SIGN_SALT,
            constants::ACCESSORY_SIGN_INFO,
        )?;
        let public = self.identity.signing_key.verifying_key().to_bytes();
        let mut ours = Vec::with_capacity(64 + self.identity.identifier.len());
        ours.extend_from_slice(&accessory_x);
        ours.extend_from_slice(&self.identity.identifier);
        ours.extend_from_slice(&public);
        let our_signature = self.identity.signing_key.sign(&ours);
        let mut inner_reply = Tlv8::new();
        inner_reply.push(tag::IDENTIFIER, self.identity.identifier.clone());
        inner_reply.push(tag::PUBLIC_KEY, public.to_vec());
        inner_reply.push(tag::SIGNATURE, our_signature.to_bytes().to_vec());
        let mut reply = Tlv8::new();
        reply.push_byte(tag::STATE, 6);
        reply.push(
            tag::ENCRYPTED_DATA,
            seal(
                &encrypt_key,
                constants::NONCE_SETUP_M6,
                &inner_reply.encode(),
            )?,
        );
        let pin = self.pin.clone().unwrap_or_default();
        self.reset();
        if !self.gate.succeed(self.owner, &pin) {
            // Hold timed out or PIN expired between M3 and M5: store nothing.
            return Ok(PairingOutcome::Reply(error_reply(6, ERROR_BUSY)));
        }
        Ok(PairingOutcome::Paired {
            reply,
            controller,
            controller_key,
        })
    }
}

impl Drop for PairSetupServer {
    fn drop(&mut self) {
        // A connection closing mid-setup must release the gate.
        self.gate.release(self.owner);
    }
}

fn verify(key: &[u8; 32], message: &[u8], signature: &[u8]) -> Result<()> {
    let key = VerifyingKey::from_bytes(key)
        .map_err(|_| AirPlayError::Protocol("not an Ed25519 key".to_owned()))?;
    let signature: Signature = signature
        .try_into()
        .map_err(|_| AirPlayError::Protocol("signature is not 64 bytes".to_owned()))?;
    key.verify(message, &signature)
        .map_err(|_| AirPlayError::Pairing(PairingError::Authentication))
}

/// The receiver's pair-verify state machine, one per connection.
pub struct PairVerifyServer {
    identity: AccessoryIdentity,
    secret: Option<X25519Secret>,
    our_public: [u8; 32],
    client_public: [u8; 32],
    shared: Option<[u8; 32]>,
}

impl std::fmt::Debug for PairVerifyServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairVerifyServer").finish_non_exhaustive()
    }
}

impl PairVerifyServer {
    /// A server.
    #[must_use]
    pub fn new(identity: AccessoryIdentity) -> Self {
        Self {
            identity,
            secret: None,
            our_public: [0; 32],
            client_public: [0; 32],
            shared: None,
        }
    }

    /// Feeds one `/pair-verify` body. `controller_key` looks up a stored controller.
    pub fn handle(
        &mut self,
        message: &Tlv8,
        rng: &mut dyn CryptoRng,
        controller_key: &dyn Fn(&[u8]) -> Option<[u8; 32]>,
    ) -> Result<PairingOutcome> {
        match state_of(message)? {
            1 => self.m1(message, rng),
            3 => self.m3(message, controller_key),
            other => Err(AirPlayError::Protocol(format!(
                "pair-verify: unexpected state {other} from a controller"
            ))),
        }
    }

    fn m1(&mut self, message: &Tlv8, rng: &mut dyn CryptoRng) -> Result<PairingOutcome> {
        let client_public: [u8; 32] = message
            .get(tag::PUBLIC_KEY)
            .and_then(|k| k.try_into().ok())
            .ok_or_else(|| {
                AirPlayError::Protocol("pair-verify M1 key is not 32 bytes".to_owned())
            })?;
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let secret = X25519Secret::from(seed);
        let public = X25519Public::from(&secret).to_bytes();
        let shared = secret
            .diffie_hellman(&X25519Public::from(client_public))
            .to_bytes();
        let session_key = hkdf_key(&shared, constants::VERIFY_SALT, constants::VERIFY_INFO)?;

        let mut signed = Vec::with_capacity(64 + self.identity.identifier.len());
        signed.extend_from_slice(&public);
        signed.extend_from_slice(&self.identity.identifier);
        signed.extend_from_slice(&client_public);
        let signature = self.identity.signing_key.sign(&signed);
        let mut inner = Tlv8::new();
        inner.push(tag::IDENTIFIER, self.identity.identifier.clone());
        inner.push(tag::SIGNATURE, signature.to_bytes().to_vec());

        let mut reply = Tlv8::new();
        reply.push_byte(tag::STATE, 2);
        reply.push(tag::PUBLIC_KEY, public.to_vec());
        reply.push(
            tag::ENCRYPTED_DATA,
            seal(&session_key, constants::NONCE_VERIFY_M2, &inner.encode())?,
        );
        self.secret = Some(secret);
        self.our_public = public;
        self.client_public = client_public;
        self.shared = Some(shared);
        Ok(PairingOutcome::Reply(reply))
    }

    fn m3(
        &mut self,
        message: &Tlv8,
        controller_key: &dyn Fn(&[u8]) -> Option<[u8; 32]>,
    ) -> Result<PairingOutcome> {
        let (Some(shared), Some(_)) = (self.shared, self.secret.as_ref()) else {
            return Err(AirPlayError::InvalidState(
                "pair-verify M3 before M1".to_owned(),
            ));
        };
        self.secret = None;
        let session_key = hkdf_key(&shared, constants::VERIFY_SALT, constants::VERIFY_INFO)?;
        let sealed = message.get(tag::ENCRYPTED_DATA).ok_or_else(|| {
            AirPlayError::Protocol("pair-verify M3 has no encrypted data".to_owned())
        })?;
        let Ok(opened) = open(&session_key, constants::NONCE_VERIFY_M3, sealed) else {
            return Ok(PairingOutcome::Reply(error_reply(4, ERROR_AUTHENTICATION)));
        };
        let inner = Tlv8::decode(&opened)?;
        let controller = inner
            .get(tag::IDENTIFIER)
            .ok_or_else(|| AirPlayError::Protocol("pair-verify M3 has no identifier".to_owned()))?
            .to_vec();
        let signature = inner
            .get(tag::SIGNATURE)
            .ok_or_else(|| AirPlayError::Protocol("pair-verify M3 has no signature".to_owned()))?;
        let Some(key) = controller_key(&controller) else {
            // Unknown controller: HAP's refusal, which sends a sender to pair-setup.
            return Ok(PairingOutcome::Reply(error_reply(4, ERROR_AUTHENTICATION)));
        };
        let mut signed = Vec::with_capacity(64 + controller.len());
        signed.extend_from_slice(&self.client_public);
        signed.extend_from_slice(&controller);
        signed.extend_from_slice(&self.our_public);
        if verify(&key, &signed, signature).is_err() {
            return Ok(PairingOutcome::Reply(error_reply(4, ERROR_AUTHENTICATION)));
        }
        let mut reply = Tlv8::new();
        reply.push_byte(tag::STATE, 4);
        Ok(PairingOutcome::Encrypt {
            reply,
            keys: Box::new(receiver_control_keys(&shared)?),
            controller: Some(controller),
        })
    }
}
