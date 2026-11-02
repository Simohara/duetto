//! HAP pairing for AirPlay 2, the sans-io half. Both exchanges are state machines over decoded
//! [`Tlv8`]s; no sockets or clock, randomness only via the injected RNG.
//! * **pair-setup** (`/pair-setup`) proves a PIN with SRP-6a (3072-bit, SHA-512). *Transient* mode
//!   uses a fixed PIN and stores nothing; refused by every tested Apple TV, accepted by a HomePod
//!   mini in an iPhone's request shape ([`TransientStyle::Ios26`]). PIN mode is untested on
//!   hardware.
//! * **pair-verify** (`/pair-verify`) does X25519 + Ed25519 and yields the ChaCha20-Poly1305 keys
//!   for the session. Validated on hardware with a Companion-derived credential.
//!
//! The constants in [`constants`] come from open receiver implementations and are assumed unless
//! marked observed; each is one named constant.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand_core::CryptoRng;
use sha2::Sha512;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::srp6a::{SrpClient, SrpClientProof};

use super::tlv8::{tag, Tlv8};
use super::{flags, Method, PairingError};
use crate::error::{AirPlayError, Result};

/// Protocol constants. Assumed unless marked observed.
pub mod constants {
    /// SRP username for pair-setup. Fixed by HAP.
    pub const SRP_USERNAME: &str = "Pair-Setup";

    /// The PIN for transient pairing; being published, it makes the exchange key agreement, not
    /// authentication.
    pub const TRANSIENT_PIN: &str = "3939";

    /// HKDF salt for deriving the control-channel keys after pair-setup.
    pub const CONTROL_SALT: &[u8] = b"Control-Salt";
    /// HKDF info for the key we encrypt outbound control traffic with.
    pub const CONTROL_WRITE_INFO: &[u8] = b"Control-Write-Encryption-Key";
    /// HKDF info for the key we decrypt inbound control traffic with.
    pub const CONTROL_READ_INFO: &[u8] = b"Control-Read-Encryption-Key";

    /// HKDF salt for the **event** channel (the receiver opens it, so the info labels are crossed;
    /// see `SessionKeys::event_keys`).
    pub const EVENTS_SALT: &[u8] = b"Events-Salt";
    /// HKDF info for the event channel's read direction (which is our *write* direction).
    pub const EVENTS_READ_INFO: &[u8] = b"Events-Read-Encryption-Key";
    /// HKDF info for the event channel's write direction (which is our *read* direction).
    pub const EVENTS_WRITE_INFO: &[u8] = b"Events-Write-Encryption-Key";

    /// HKDF salt for the pair-verify session key.
    pub const VERIFY_SALT: &[u8] = b"Pair-Verify-Encrypt-Salt";
    /// HKDF info for the pair-verify session key.
    pub const VERIFY_INFO: &[u8] = b"Pair-Verify-Encrypt-Info";

    /// HKDF salt for the key that seals the pair-setup M5/M6 sub-TLVs.
    pub const SETUP_ENCRYPT_SALT: &[u8] = b"Pair-Setup-Encrypt-Salt";
    /// HKDF info for the same.
    pub const SETUP_ENCRYPT_INFO: &[u8] = b"Pair-Setup-Encrypt-Info";
    /// HKDF salt for the value we sign in M5, binding our long-term key to the SRP exchange.
    pub const CONTROLLER_SIGN_SALT: &[u8] = b"Pair-Setup-Controller-Sign-Salt";
    /// HKDF info for the same.
    pub const CONTROLLER_SIGN_INFO: &[u8] = b"Pair-Setup-Controller-Sign-Info";
    /// HKDF salt for the value the receiver signs in M6.
    pub const ACCESSORY_SIGN_SALT: &[u8] = b"Pair-Setup-Accessory-Sign-Salt";
    /// HKDF info for the same.
    pub const ACCESSORY_SIGN_INFO: &[u8] = b"Pair-Setup-Accessory-Sign-Info";

    /// Nonce for the sealed sub-TLV we send in pair-setup M5.
    pub const NONCE_SETUP_M5: &[u8] = b"PS-Msg05";
    /// Nonce for the sealed sub-TLV the receiver sends in pair-setup M6.
    pub const NONCE_SETUP_M6: &[u8] = b"PS-Msg06";

    /// Nonce for the sealed sub-TLV the receiver sends in pair-verify M2.
    pub const NONCE_VERIFY_M2: &[u8] = b"PV-Msg02";
    /// Nonce for the sealed sub-TLV we send in pair-verify M3.
    pub const NONCE_VERIFY_M3: &[u8] = b"PV-Msg03";

    /// Identifier presented when the caller supplies none; stable across restarts. Prefer
    /// [`super::PairVerify::with_client_name`] or [`super::PairSetup::with_identity`].
    pub const CLIENT_IDENTIFIER: &str = crate::DEFAULT_CLIENT_NAME;

    /// Header naming the HomeKit pairing flavour. Observed: without it a current Apple TV answers
    /// `/pair-setup` with 470.
    pub const HKP_HEADER: &str = "X-Apple-HKP";

    /// Header value for transient pair-setup. Observed on `AppleTV14,1` / tvOS 23L243: `1` returns
    /// the SRP challenge; 2, 3, 5, 6 a pairing error; 0, 4 a 470.
    pub const HKP_TRANSIENT: &str = "1";

    /// Transient pair-setup header value as an iPhone sends it (observed: iOS 26.7 sends `4`; an
    /// `AppleTV14,1` refuses it with 470). Equals [`crate::sequence::IOS_TRANSIENT_HKP`].
    pub const HKP_TRANSIENT_IOS: &str = "4";

    /// `Content-Type` on the iPhone's `/pair-setup` requests: a binary-plist type on a TLV8 body
    /// (observed).
    pub const IOS_PAIR_SETUP_CONTENT_TYPE: &str = "application/x-apple-binary-plist";

    /// Header value for pair-verify against a PIN-derived credential and `/pair-pin-start`
    /// (observed from a real Mac); `6` is HomeKit/iCloud.
    pub const HKP_VERIFY: &str = "3";

    /// Header value for PIN pair-setup and `/pair-pin-start` (observed); aliases [`HKP_VERIFY`].
    pub const HKP_PIN: &str = HKP_VERIFY;

    /// Header value for pair-verify against a HomeKit/iCloud credential. Observed but unusable
    /// here.
    pub const HKP_HOMEKIT: &str = "6";

    /// Header a real sender sends on every `pair-verify` (observed); effect untested.
    pub const PD_HEADER: &str = "X-Apple-PD";

    /// Value for [`PD_HEADER`].
    pub const PD_VALUE: &str = "1";

    /// Header carrying the sender's device name, which a receiver shows in its own UI.
    pub const CLIENT_NAME_HEADER: &str = "X-Apple-Client-Name";

    /// The endpoint that makes the receiver display a four-digit PIN.
    pub const PIN_START_PATH: &str = "/pair-pin-start";
}

/// What the caller should do next.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Step {
    /// POST this TLV8 body to the endpoint and feed the reply back in.
    Send(Tlv8),
    /// The exchange finished; the derived material is attached.
    Done(Box<SessionKeys>),
    /// A PIN pair-setup finished and the receiver stored a pairing; persist these and run
    /// pair-verify on later connections.
    Paired(Box<HapCredentials>),
    /// The receiver wants a PIN from the user before we can continue.
    NeedPin,
}

/// A completed HAP PIN pairing, the credential a real Apple sender holds. Not interchangeable with
/// `LegacyCredentials`; the storage string is pyatv's.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct HapCredentials {
    /// The receiver's long-term Ed25519 public key.
    pub device_public: [u8; 32],
    /// Our long-term Ed25519 private seed.
    pub client_secret: [u8; 32],
    /// The receiver's pairing identifier, as raw bytes.
    pub device_id: Vec<u8>,
    /// Our pairing identifier, as raw bytes.
    pub client_id: Vec<u8>,
}

impl std::fmt::Debug for HapCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HapCredentials")
            .field("device_id", &String::from_utf8_lossy(&self.device_id))
            .field("client_secret", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl HapCredentials {
    /// Serializes as `ltpk:ltsk:atv_id:client_id`, all hex — pyatv's format.
    #[must_use]
    pub fn to_storage_string(&self) -> String {
        format!(
            "{}:{}:{}:{}",
            hex::encode(self.device_public),
            hex::encode(self.client_secret),
            hex::encode(&self.device_id),
            hex::encode(&self.client_id)
        )
    }

    /// Parses a storage string.
    pub fn parse(raw: &str) -> Result<Self> {
        let parts: Vec<&str> = raw.trim().split(':').collect();
        if parts.len() != 4 {
            return Err(AirPlayError::Credentials(
                "HAP credentials must be four colon-separated hex fields".to_owned(),
            ));
        }
        let field = |index: usize, what: &str| -> Result<Vec<u8>> {
            hex::decode(parts[index]).map_err(|_| {
                AirPlayError::Credentials(format!("HAP credentials: {what} is not hex"))
            })
        };
        let device_public: [u8; 32] = field(0, "the receiver key")?.try_into().map_err(|_| {
            AirPlayError::Credentials("the receiver key is not 32 bytes".to_owned())
        })?;
        let client_secret: [u8; 32] = field(1, "our key")?
            .try_into()
            .map_err(|_| AirPlayError::Credentials("our key is not 32 bytes".to_owned()))?;
        Ok(Self {
            device_public,
            client_secret,
            device_id: field(2, "the receiver identifier")?,
            client_id: field(3, "our identifier")?,
        })
    }

    /// Our Ed25519 signing key.
    #[must_use]
    pub fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.client_secret)
    }

    /// The receiver's Ed25519 verifying key, or an error when the stored bytes are not a point.
    pub fn device_key(&self) -> Result<VerifyingKey> {
        VerifyingKey::from_bytes(&self.device_public).map_err(|_| {
            AirPlayError::Credentials("the stored receiver key is not valid".to_owned())
        })
    }
}

/// Key material produced by a completed exchange.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SessionKeys {
    /// The raw SRP or X25519 shared secret, kept for deriving further keys.
    pub shared_secret: Vec<u8>,
    /// Key for traffic we send.
    pub write_key: [u8; 32],
    /// Key for traffic we receive.
    pub read_key: [u8; 32],
}

impl std::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionKeys")
            .field("shared_secret", &"<redacted>")
            .field("write_key", &"<redacted>")
            .field("read_key", &"<redacted>")
            .finish()
    }
}

/// One connection's two ChaCha20-Poly1305 keys from this side's view; zeroed on drop, `Debug` shows
/// nothing.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct DirectionalKeys {
    /// Seals what this side sends.
    pub write: [u8; 32],
    /// Opens what this side receives.
    pub read: [u8; 32],
}

impl DirectionalKeys {
    /// The same keys from the other side's point of view.
    #[must_use]
    pub fn reversed(&self) -> Self {
        Self {
            write: self.read,
            read: self.write,
        }
    }

    /// A transport that seals with [`Self::write`] and opens with [`Self::read`].
    #[must_use]
    pub fn transport(&self) -> crate::cipher::EncryptedTransport {
        crate::cipher::EncryptedTransport::from_keys(&self.write, &self.read)
    }
}

impl std::fmt::Debug for DirectionalKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DirectionalKeys(<redacted>)")
    }
}

/// Which pair-setup variant to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SetupMode {
    /// Fixed PIN, nothing stored. Refused by every tested Apple TV; accepted by a HomePod mini in
    /// the iPhone's shape ([`TransientStyle::Ios26`]).
    Transient,
    /// The receiver displays a PIN the user types. Produces a stored pairing.
    Pin,
}

/// How a **transient** pair-setup's requests are shaped; the SRP exchange is identical in every
/// style.
///
/// | | [`Self::Classic`] | [`Self::Ios26`] |
/// |---|---|---|
/// | `X-Apple-HKP` | `1` ([`constants::HKP_TRANSIENT`]) | `4` ([`constants::HKP_TRANSIENT_IOS`]) |
/// | M1 body | `06 01 01 00 01 00 13 04 10 00 00 01` (12 bytes: state, method, flags `TRANSIENT \| SPLIT` as a `u32`) | `00 01 00 06 01 01 13 01 10` (9 bytes: method, state, flags `TRANSIENT` in one byte) |
/// | `Content-Type` | `application/octet-stream` | `application/x-apple-binary-plist` |
/// | `X-Apple-PD` | `1` | absent |
/// | `X-Apple-AbsoluteTime` | absent | seconds since 2001 ([`crate::sequence::ABSOLUTE_TIME_HEADER`]) |
/// | before M1, same connection | nothing | pair-verify M1 with `X-Apple-HKP: 6`, then `3`, each abandoned after M2 |
///
/// `Ios26` is the iPhone's (observed). `Classic` is what an Apple TV and a HomePod answered with a
/// salt, then refused at the proof. [`Self::Ios26WithoutVerifyProbes`] omits the two pair-verifies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum TransientStyle {
    /// The classic shape.
    #[default]
    Classic,
    /// An iPhone's (iOS 26.7), including the two abandoned pair-verify probes before it.
    Ios26,
    /// An iPhone's pair-setup requests without the pair-verify probes before them.
    Ios26WithoutVerifyProbes,
    /// pyatv 0.18.0: HKP 4, octet-stream, compact transient flag, no probes.
    /// The caller first sends pyatv's `/pair-pin-start` request.
    Pyatv,
}

impl TransientStyle {
    /// Every style, for a command line's help.
    pub const ALL: [Self; 4] = [
        Self::Classic,
        Self::Ios26,
        Self::Ios26WithoutVerifyProbes,
        Self::Pyatv,
    ];

    /// The name a command line uses: `classic`, `ios26`, `ios26-bare`.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Classic => "classic",
            Self::Ios26 => "ios26",
            Self::Ios26WithoutVerifyProbes => "ios26-bare",
            Self::Pyatv => "pyatv",
        }
    }

    /// The style a [`Self::name`] names.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.name() == name)
    }

    fn is_ios(self) -> bool {
        matches!(self, Self::Ios26 | Self::Ios26WithoutVerifyProbes)
    }

    /// `X-Apple-HKP` on the `/pair-setup` requests.
    #[must_use]
    pub fn hkp(self) -> &'static str {
        if self.is_ios() || matches!(self, Self::Pyatv) {
            constants::HKP_TRANSIENT_IOS
        } else {
            constants::HKP_TRANSIENT
        }
    }

    /// `Content-Type` on the `/pair-setup` requests.
    #[must_use]
    pub fn content_type(self) -> &'static str {
        if self.is_ios() {
            constants::IOS_PAIR_SETUP_CONTENT_TYPE
        } else {
            "application/octet-stream"
        }
    }

    /// Whether the `/pair-setup` requests carry `X-Apple-PD: 1`.
    #[must_use]
    pub fn sends_pd(self) -> bool {
        matches!(self, Self::Classic)
    }

    /// Whether every pairing request carries `X-Apple-AbsoluteTime`.
    #[must_use]
    pub fn sends_absolute_time(self) -> bool {
        self.is_ios()
    }

    /// The `X-Apple-HKP` values of the pair-verify M1s sent (abandoned after M2) before pair-setup
    /// M1; empty for none.
    #[must_use]
    pub fn verify_probe_hkps(self) -> &'static [u8] {
        match self {
            Self::Ios26 => &crate::sequence::IOS_PAIR_VERIFY_HKP_LADDER,
            Self::Classic | Self::Ios26WithoutVerifyProbes | Self::Pyatv => &[],
        }
    }
}

/// One line naming what a pairing TLV8 carries (types by name, short values as numbers, longer as
/// lengths), safe to print: no key material. `retryDelay` is little-endian.
#[must_use]
pub fn describe_tlv(message: &Tlv8) -> String {
    let parts: Vec<String> = message
        .iter()
        .map(|(t, value)| {
            let name = match t {
                tag::METHOD => "method",
                tag::IDENTIFIER => "identifier",
                tag::SALT => "salt",
                tag::PUBLIC_KEY => "publicKey",
                tag::PROOF => "proof",
                tag::ENCRYPTED_DATA => "encryptedData",
                tag::STATE => "state",
                tag::ERROR => "error",
                tag::RETRY_DELAY => "retryDelay",
                tag::CERTIFICATE => "certificate",
                tag::SIGNATURE => "signature",
                tag::PERMISSIONS => "permissions",
                tag::FRAGMENT_DATA => "fragmentData",
                tag::FRAGMENT_LAST => "fragmentLast",
                tag::NAME => "name",
                tag::FLAGS => "flags",
                tag::SEPARATOR => "separator",
                _ => "",
            };
            let label = if name.is_empty() {
                format!("type{t:#04x}")
            } else {
                name.to_owned()
            };
            let numeric = matches!(
                t,
                tag::METHOD
                    | tag::STATE
                    | tag::ERROR
                    | tag::RETRY_DELAY
                    | tag::PERMISSIONS
                    | tag::FLAGS
            );
            if numeric && !value.is_empty() && value.len() <= 4 {
                let mut buf = [0u8; 4];
                buf[..value.len()].copy_from_slice(value);
                let n = u32::from_le_bytes(buf);
                if t == tag::FLAGS {
                    format!("{label}={n:#x}")
                } else {
                    format!("{label}={n}")
                }
            } else {
                format!("{label}({} bytes)", value.len())
            }
        })
        .collect();
    if parts.is_empty() {
        "(empty)".to_owned()
    } else {
        parts.join(" ")
    }
}

/// The pair-setup state machine. Holds secret key material, zeroized on drop.
pub struct PairSetup {
    mode: SetupMode,
    transient_style: TransientStyle,
    state: SetupState,
    client_secret: [u8; 32],
    ltsk_seed: [u8; 32],
    client_id: Vec<u8>,
    pin: Option<String>,
    /// Filled in at M3. Holds the expected server proof (checked at M4) and the session key.
    proof: Option<SrpClientProof>,
    /// M2, held while the user reads the PIN off the screen (the challenge cannot be re-requested).
    challenge: Option<Tlv8>,
    method_first: bool,
    m5_extra: Tlv8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SetupState {
    Start,
    AwaitingChallenge,
    AwaitingProof,
    AwaitingExchange,
    Finished,
    Failed,
}

impl std::fmt::Debug for PairSetup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairSetup")
            .field("mode", &self.mode)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl Drop for PairSetup {
    fn drop(&mut self) {
        self.client_secret.zeroize();
        self.ltsk_seed.zeroize();
        if let Some(ref mut pin) = self.pin {
            pin.zeroize();
        }
    }
}

impl PairSetup {
    /// Creates a pair-setup run. `rng` supplies the SRP ephemeral and the Ed25519 seed.
    pub fn new(mode: SetupMode, rng: &mut dyn CryptoRng) -> Self {
        let mut client_secret = [0u8; 32];
        rng.fill_bytes(&mut client_secret);
        let mut ltsk_seed = [0u8; 32];
        rng.fill_bytes(&mut ltsk_seed);
        let mut id = [0u8; 16];
        rng.fill_bytes(&mut id);
        Self::with_identity(
            mode,
            uppercase_uuid(&id).into_bytes(),
            client_secret,
            ltsk_seed,
        )
    }

    /// Creates a pair-setup run with a caller-supplied identity, so an exchange replays exactly.
    #[must_use]
    pub fn with_identity(
        mode: SetupMode,
        client_id: Vec<u8>,
        client_secret: [u8; 32],
        ltsk_seed: [u8; 32],
    ) -> Self {
        Self {
            mode,
            transient_style: TransientStyle::Classic,
            state: SetupState::Start,
            client_secret,
            ltsk_seed,
            client_id,
            pin: match mode {
                SetupMode::Transient => Some(constants::TRANSIENT_PIN.to_owned()),
                SetupMode::Pin => None,
            },
            proof: None,
            challenge: None,
            method_first: false,
            m5_extra: Tlv8::new(),
        }
    }

    /// Writes a PIN M1 as `Method, State` (pyatv's and Companion's order).
    #[must_use]
    pub fn with_method_first(mut self) -> Self {
        self.method_first = true;
        self
    }

    /// Items to append to the sealed M5 sub-TLV (Companion sends its display name).
    pub fn set_m5_extra(&mut self, extra: Tlv8) {
        self.m5_extra = extra;
    }

    /// Creates a **transient** pair-setup run laid out in `style`; [`Self::new`] with
    /// [`SetupMode::Transient`] is [`TransientStyle::Classic`].
    pub fn transient(style: TransientStyle, rng: &mut dyn CryptoRng) -> Self {
        Self::new(SetupMode::Transient, rng).with_transient_style(style)
    }

    /// Sets how a transient M1 is laid out. Has no effect on a PIN setup.
    #[must_use]
    pub fn with_transient_style(mut self, style: TransientStyle) -> Self {
        self.transient_style = style;
        self
    }

    /// Supplies the PIN the receiver displayed. Only meaningful in [`SetupMode::Pin`].
    pub fn set_pin(&mut self, pin: impl Into<String>) {
        self.pin = Some(pin.into());
    }

    /// Supplies the PIN and resumes from the challenge already received.
    pub fn resume_with_pin(&mut self, pin: impl Into<String>) -> Result<Step> {
        self.set_pin(pin);
        let challenge = self.challenge.take().ok_or_else(|| {
            AirPlayError::InvalidState(
                "the receiver has not shown a PIN yet, so there is nothing to answer".to_owned(),
            )
        })?;
        self.handle_challenge(&challenge)
    }

    /// Produces M1, the message that opens the exchange.
    pub fn start(&mut self) -> Result<Tlv8> {
        if self.state != SetupState::Start {
            return Err(AirPlayError::InvalidState(
                "pair-setup has already started".to_owned(),
            ));
        }

        let mut message = Tlv8::new();
        match (self.mode, self.transient_style) {
            (SetupMode::Transient, TransientStyle::Classic) => {
                message.push_byte(tag::STATE, 1);
                message.push_byte(tag::METHOD, Method::PairSetup as u8);
                message.push_u32(tag::FLAGS, flags::TRANSIENT | flags::SPLIT);
            }
            (SetupMode::Transient, _) => {
                // Observed from an iPhone: `00 01 00 | 06 01 01 | 13 01 10`, method first and
                // `TRANSIENT` alone.
                message.push_byte(tag::METHOD, Method::PairSetup as u8);
                message.push_byte(tag::STATE, 1);
                message.push_u32_compact(tag::FLAGS, flags::TRANSIENT);
            }
            (SetupMode::Pin, _) if self.method_first => {
                message.push_byte(tag::METHOD, Method::PairSetup as u8);
                message.push_byte(tag::STATE, 1);
            }
            (SetupMode::Pin, _) => {
                // Method::PairSetup (0), not PairSetupWithAuth (1); assumed to match pyatv and
                // Companion.
                message.push_byte(tag::STATE, 1);
                message.push_byte(tag::METHOD, Method::PairSetup as u8);
            }
        }

        self.state = SetupState::AwaitingChallenge;
        Ok(message)
    }

    /// Feeds a reply in and returns what to do next.
    pub fn handle(&mut self, reply: &Tlv8) -> Result<Step> {
        if let Some(code) = reply.get_byte(tag::ERROR) {
            self.state = SetupState::Failed;
            return Err(AirPlayError::Pairing(PairingError::from_code(code)));
        }

        match self.state {
            SetupState::AwaitingChallenge => self.handle_challenge(reply),
            SetupState::AwaitingProof => self.handle_proof(reply),
            SetupState::AwaitingExchange => self.handle_exchange(reply),
            SetupState::Start => Err(AirPlayError::InvalidState(
                "pair-setup has not started".to_owned(),
            )),
            SetupState::Finished | SetupState::Failed => Err(AirPlayError::InvalidState(
                "pair-setup is already over".to_owned(),
            )),
        }
    }

    /// M2 in, M3 out: the receiver sent its SRP public value and salt.
    fn handle_challenge(&mut self, reply: &Tlv8) -> Result<Step> {
        expect_state(reply, 2)?;

        let Some(pin) = self.pin.clone() else {
            // A PIN-mode receiver now shows digits; hold the challenge for
            // [`Self::resume_with_pin`].
            self.challenge = Some(reply.clone());
            return Ok(Step::NeedPin);
        };

        let salt = reply
            .get(tag::SALT)
            .ok_or_else(|| AirPlayError::Protocol("pair-setup M2 has no salt".to_owned()))?;
        let server_public = reply
            .get(tag::PUBLIC_KEY)
            .ok_or_else(|| AirPlayError::Protocol("pair-setup M2 has no public key".to_owned()))?;

        let client = SrpClient::with_secret(constants::SRP_USERNAME, &pin, &self.client_secret);
        let proof = client
            .process_challenge(salt, server_public)
            .ok_or_else(|| {
                AirPlayError::Protocol(
                    "receiver sent an invalid SRP public value (B = 0)".to_owned(),
                )
            })?;

        let mut message = Tlv8::new();
        message.push_byte(tag::STATE, 3);
        message.push(tag::PUBLIC_KEY, proof.a_pub.clone());
        message.push(tag::PROOF, proof.m1.clone());

        self.proof = Some(proof);
        self.state = SetupState::AwaitingProof;
        Ok(Step::Send(message))
    }

    /// M4 in: the receiver proved it knows the PIN. Transient ends with session keys; PIN continues
    /// to M5/M6.
    fn handle_proof(&mut self, reply: &Tlv8) -> Result<Step> {
        expect_state(reply, 4)?;

        // Without this check anything answering on port 7000 could hand us a key.
        let server_proof = reply
            .get(tag::PROOF)
            .ok_or_else(|| AirPlayError::Protocol("pair-setup M4 has no proof".to_owned()))?;
        let proof = self.proof.as_ref().ok_or_else(|| {
            AirPlayError::InvalidState("pair-setup has no proof state".to_owned())
        })?;

        // Constant-time compare, so a mismatch cannot be probed byte by byte.
        if !constant_time_eq(server_proof, &proof.m2) {
            self.state = SetupState::Failed;
            return Err(AirPlayError::Protocol(
                "pair-setup M4 proof did not verify; the receiver does not know the PIN".to_owned(),
            ));
        }

        if self.mode == SetupMode::Transient {
            self.state = SetupState::Finished;
            return Ok(Step::Done(Box::new(derive_control_keys(
                &proof.session_key,
            )?)));
        }

        let controller_x = hkdf_key(
            &proof.session_key,
            constants::CONTROLLER_SIGN_SALT,
            constants::CONTROLLER_SIGN_INFO,
        )?;
        let encrypt_key = hkdf_key(
            &proof.session_key,
            constants::SETUP_ENCRYPT_SALT,
            constants::SETUP_ENCRYPT_INFO,
        )?;
        let signing = SigningKey::from_bytes(&self.ltsk_seed);
        let public = signing.verifying_key().to_bytes();

        let mut signed = Vec::with_capacity(64 + self.client_id.len());
        signed.extend_from_slice(&controller_x);
        signed.extend_from_slice(&self.client_id);
        signed.extend_from_slice(&public);
        let signature: Signature = signing.sign(&signed);

        let mut inner = Tlv8::new();
        inner.push(tag::IDENTIFIER, self.client_id.clone());
        inner.push(tag::PUBLIC_KEY, public.to_vec());
        inner.push(tag::SIGNATURE, signature.to_bytes().to_vec());
        for (extra_tag, value) in self.m5_extra.iter() {
            inner.push(extra_tag, value);
        }

        let sealed = seal(&encrypt_key, constants::NONCE_SETUP_M5, &inner.encode())?;
        let mut message = Tlv8::new();
        message.push_byte(tag::STATE, 5);
        message.push(tag::ENCRYPTED_DATA, sealed);

        self.state = SetupState::AwaitingExchange;
        Ok(Step::Send(message))
    }

    /// M6 in: the receiver hands over its identity and the pairing is stored on both sides.
    fn handle_exchange(&mut self, reply: &Tlv8) -> Result<Step> {
        expect_state(reply, 6)?;
        let proof = self.proof.as_ref().ok_or_else(|| {
            AirPlayError::InvalidState("pair-setup has no proof state".to_owned())
        })?;
        let sealed = reply.get(tag::ENCRYPTED_DATA).ok_or_else(|| {
            AirPlayError::Protocol("pair-setup M6 has no encrypted data".to_owned())
        })?;

        let encrypt_key = hkdf_key(
            &proof.session_key,
            constants::SETUP_ENCRYPT_SALT,
            constants::SETUP_ENCRYPT_INFO,
        )?;
        let opened = open(&encrypt_key, constants::NONCE_SETUP_M6, sealed)
            .map_err(|_| AirPlayError::Protocol("pair-setup M6 did not authenticate".to_owned()))?;
        let inner = Tlv8::decode(&opened)?;

        let device_id = inner
            .get(tag::IDENTIFIER)
            .ok_or_else(|| AirPlayError::Protocol("pair-setup M6 has no identifier".to_owned()))?
            .to_vec();
        let device_public: [u8; 32] = inner
            .get(tag::PUBLIC_KEY)
            .ok_or_else(|| AirPlayError::Protocol("pair-setup M6 has no public key".to_owned()))?
            .try_into()
            .map_err(|_| {
                AirPlayError::Protocol("pair-setup M6 public key is not 32 bytes".to_owned())
            })?;
        let signature = inner
            .get(tag::SIGNATURE)
            .ok_or_else(|| AirPlayError::Protocol("pair-setup M6 has no signature".to_owned()))?;

        // This signature alone binds the stored key to the SRP exchange; skipping it lets anything
        // on port 7000 substitute its key.
        let accessory_x = hkdf_key(
            &proof.session_key,
            constants::ACCESSORY_SIGN_SALT,
            constants::ACCESSORY_SIGN_INFO,
        )?;
        let mut signed = Vec::with_capacity(64 + device_id.len());
        signed.extend_from_slice(&accessory_x);
        signed.extend_from_slice(&device_id);
        signed.extend_from_slice(&device_public);
        let device_key = VerifyingKey::from_bytes(&device_public).map_err(|_| {
            AirPlayError::Protocol(
                "pair-setup M6 public key is not a valid Ed25519 point".to_owned(),
            )
        })?;
        let parsed: Signature = signature.try_into().map_err(|_| {
            AirPlayError::Protocol("pair-setup M6 signature is not 64 bytes".to_owned())
        })?;
        device_key.verify(&signed, &parsed).map_err(|_| {
            AirPlayError::Protocol("pair-setup M6 signature did not verify".to_owned())
        })?;

        self.state = SetupState::Finished;
        Ok(Step::Paired(Box::new(HapCredentials {
            device_public,
            client_secret: self.ltsk_seed,
            device_id,
            client_id: self.client_id.clone(),
        })))
    }
}

/// Length-independent, content-constant-time byte comparison. Public for reuse by protocol crates.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

fn expect_state(reply: &Tlv8, expected: u8) -> Result<()> {
    match reply.get_byte(tag::STATE) {
        Some(state) if state == expected => Ok(()),
        Some(state) => Err(AirPlayError::Protocol(format!(
            "expected pairing state {expected}, receiver sent {state}"
        ))),
        None => Err(AirPlayError::Protocol(
            "pairing reply carries no state".to_owned(),
        )),
    }
}

impl SessionKeys {
    /// Keys from a shared secret with HKDF-SHA512 under `salt`: write key from `write_info`, read
    /// key from `read_info`.
    pub fn derive(
        shared_secret: &[u8],
        salt: &[u8],
        write_info: &[u8],
        read_info: &[u8],
    ) -> Result<Self> {
        Ok(Self {
            shared_secret: shared_secret.to_vec(),
            write_key: hkdf_key(shared_secret, salt, write_info)?,
            read_key: hkdf_key(shared_secret, salt, read_info)?,
        })
    }

    /// The keys for the **event channel**, from this sender's view: the control channel's secret
    /// with a different salt and the two labels **crossed** (the receiver opens it).
    /// # Errors
    /// HKDF refusing the expansion (it does not for these lengths).
    pub fn event_keys(&self) -> Result<DirectionalKeys> {
        Ok(DirectionalKeys {
            write: hkdf_key(
                &self.shared_secret,
                constants::EVENTS_SALT,
                constants::EVENTS_READ_INFO,
            )?,
            read: hkdf_key(
                &self.shared_secret,
                constants::EVENTS_SALT,
                constants::EVENTS_WRITE_INFO,
            )?,
        })
    }
}

/// Derives the control-channel keys from a completed pair-setup.
fn derive_control_keys(shared_key: &[u8]) -> Result<SessionKeys> {
    SessionKeys::derive(
        shared_key,
        constants::CONTROL_SALT,
        constants::CONTROL_WRITE_INFO,
        constants::CONTROL_READ_INFO,
    )
}

/// HKDF-SHA512 down to a 32-byte ChaCha20-Poly1305 key. Public so Companion pairing can reuse it.
pub fn hkdf_key(secret: &[u8], salt: &[u8], info: &[u8]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha512>::new(Some(salt), secret);
    let mut key = [0u8; 32];
    hk.expand(info, &mut key)
        .map_err(|_| AirPlayError::Protocol("HKDF expand failed".to_owned()))?;
    Ok(key)
}

/// The pair-verify state machine, run after pair-setup or alone against a stored pairing; yields
/// the session keys.
pub struct PairVerify {
    state: VerifyState,
    secret: X25519Secret,
    public: X25519Public,
    identity: SigningKey,
    /// The identifier we present in M3; must match the one the receiver saw at pair-setup.
    client_id: Vec<u8>,
    /// The receiver we expect, when we hold a stored pairing; `None` on a transient session (no key
    /// to check its signature).
    expected_device: Option<(Vec<u8>, VerifyingKey)>,
    session_key: Option<[u8; 32]>,
    shared_secret: Option<[u8; 32]>,
}

impl std::fmt::Debug for PairVerify {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairVerify")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VerifyState {
    Start,
    AwaitingKeyExchange,
    AwaitingConfirmation,
    Finished,
    Failed,
}

impl PairVerify {
    /// Creates a pair-verify run with a fresh ephemeral key and the given long-term identity;
    /// persist the identity.
    pub fn new(identity: SigningKey, rng: &mut dyn CryptoRng) -> Self {
        Self::with_client_name(identity, rng, constants::CLIENT_IDENTIFIER)
    }

    /// Like [`Self::new`], presenting `client_name` instead of [`constants::CLIENT_IDENTIFIER`].
    /// Embedders should use this.
    pub fn with_client_name(
        identity: SigningKey,
        rng: &mut dyn CryptoRng,
        client_name: &str,
    ) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        Self::with_ephemeral(identity, client_name.as_bytes().to_vec(), None, seed)
    }

    /// Creates a pair-verify run against a **stored** pairing: presents its identifier and checks
    /// the receiver's signature.
    pub fn with_credentials(credentials: &HapCredentials, rng: &mut dyn CryptoRng) -> Result<Self> {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        Ok(Self::with_ephemeral(
            credentials.signing_key(),
            credentials.client_id.clone(),
            Some((credentials.device_id.clone(), credentials.device_key()?)),
            seed,
        ))
    }

    /// Creates a pair-verify run with a caller-supplied ephemeral, so an exchange replays exactly.
    #[must_use]
    pub fn with_ephemeral(
        identity: SigningKey,
        client_id: Vec<u8>,
        expected_device: Option<(Vec<u8>, VerifyingKey)>,
        seed: [u8; 32],
    ) -> Self {
        let secret = X25519Secret::from(seed);
        let public = X25519Public::from(&secret);
        Self {
            state: VerifyState::Start,
            secret,
            public,
            identity,
            client_id,
            expected_device,
            session_key: None,
            shared_secret: None,
        }
    }

    /// Generates a fresh long-term identity. Callers persist the bytes and reuse them.
    pub fn generate_identity(rng: &mut dyn CryptoRng) -> SigningKey {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        SigningKey::from_bytes(&seed)
    }

    /// Our Ed25519 public key, which a receiver stores when a pairing is created.
    #[must_use]
    pub fn identity_public(&self) -> VerifyingKey {
        self.identity.verifying_key()
    }

    /// Produces M1: our ephemeral X25519 public key.
    pub fn start(&mut self) -> Result<Tlv8> {
        if self.state != VerifyState::Start {
            return Err(AirPlayError::InvalidState(
                "pair-verify has already started".to_owned(),
            ));
        }

        let mut message = Tlv8::new();
        message.push_byte(tag::STATE, 1);
        message.push(tag::PUBLIC_KEY, self.public.as_bytes().to_vec());

        self.state = VerifyState::AwaitingKeyExchange;
        Ok(message)
    }

    /// Feeds a reply in and returns what to do next.
    pub fn handle(&mut self, reply: &Tlv8) -> Result<Step> {
        if let Some(code) = reply.get_byte(tag::ERROR) {
            self.state = VerifyState::Failed;
            return Err(AirPlayError::Pairing(PairingError::from_code(code)));
        }

        match self.state {
            VerifyState::AwaitingKeyExchange => self.handle_key_exchange(reply),
            VerifyState::AwaitingConfirmation => {
                expect_state(reply, 4)?;
                self.state = VerifyState::Finished;
                let shared = self.shared_secret.ok_or_else(|| {
                    AirPlayError::InvalidState("pair-verify has no shared secret".to_owned())
                })?;
                Ok(Step::Done(Box::new(derive_control_keys(&shared)?)))
            }
            VerifyState::Start => Err(AirPlayError::InvalidState(
                "pair-verify has not started".to_owned(),
            )),
            VerifyState::Finished | VerifyState::Failed => Err(AirPlayError::InvalidState(
                "pair-verify is already over".to_owned(),
            )),
        }
    }

    /// M2 in, M3 out: the receiver sent its ephemeral key plus a sealed, signed identity.
    fn handle_key_exchange(&mut self, reply: &Tlv8) -> Result<Step> {
        expect_state(reply, 2)?;

        let peer_public: [u8; 32] = reply
            .get(tag::PUBLIC_KEY)
            .ok_or_else(|| AirPlayError::Protocol("pair-verify M2 has no public key".to_owned()))?
            .try_into()
            .map_err(|_| {
                AirPlayError::Protocol("pair-verify M2 public key is not 32 bytes".to_owned())
            })?;
        let sealed = reply.get(tag::ENCRYPTED_DATA).ok_or_else(|| {
            AirPlayError::Protocol("pair-verify M2 has no encrypted data".to_owned())
        })?;

        let shared = self
            .secret
            .diffie_hellman(&X25519Public::from(peer_public))
            .to_bytes();
        let session_key = hkdf_key(&shared, constants::VERIFY_SALT, constants::VERIFY_INFO)?;

        let opened = open(&session_key, constants::NONCE_VERIFY_M2, sealed).map_err(|_| {
            AirPlayError::Protocol("pair-verify M2 did not authenticate".to_owned())
        })?;
        let inner = Tlv8::decode(&opened)?;

        let peer_identifier = inner
            .get(tag::IDENTIFIER)
            .ok_or_else(|| AirPlayError::Protocol("pair-verify M2 has no identifier".to_owned()))?
            .to_vec();
        let signature_bytes = inner
            .get(tag::SIGNATURE)
            .ok_or_else(|| AirPlayError::Protocol("pair-verify M2 has no signature".to_owned()))?;

        // The receiver signs peerPublic || identifier || ourPublic; checkable only with its stored
        // public key.
        if let Some((expected_id, device_key)) = &self.expected_device {
            if peer_identifier != *expected_id {
                self.state = VerifyState::Failed;
                return Err(AirPlayError::PairVerifyRefused(
                    "the receiver answering is not the one this pairing belongs to".to_owned(),
                ));
            }
            Self::verify_peer_signature(
                device_key,
                &peer_public,
                &peer_identifier,
                self.public.as_bytes(),
                signature_bytes,
            )
            .inspect_err(|_| self.state = VerifyState::Failed)?;
        }

        let mut inner_reply = Tlv8::new();
        inner_reply.push(tag::IDENTIFIER, self.client_id.clone());

        let mut signed = Vec::with_capacity(64 + self.client_id.len());
        signed.extend_from_slice(self.public.as_bytes());
        signed.extend_from_slice(&self.client_id);
        signed.extend_from_slice(&peer_public);
        let signature: Signature = self.identity.sign(&signed);
        inner_reply.push(tag::SIGNATURE, signature.to_bytes().to_vec());

        let sealed_reply = seal(
            &session_key,
            constants::NONCE_VERIFY_M3,
            &inner_reply.encode(),
        )?;

        let mut message = Tlv8::new();
        message.push_byte(tag::STATE, 3);
        message.push(tag::ENCRYPTED_DATA, sealed_reply);

        self.session_key = Some(session_key);
        self.shared_secret = Some(shared);
        self.state = VerifyState::AwaitingConfirmation;
        Ok(Step::Send(message))
    }

    /// Verifies a receiver signature against a public key trusted from a stored pairing.
    pub fn verify_peer_signature(
        peer_identity: &VerifyingKey,
        peer_public: &[u8; 32],
        peer_identifier: &[u8],
        our_public: &[u8; 32],
        signature: &[u8],
    ) -> Result<()> {
        let signature: Signature = signature
            .try_into()
            .map_err(|_| AirPlayError::Protocol("signature is not 64 bytes".to_owned()))?;
        let mut signed = Vec::with_capacity(64 + peer_identifier.len());
        signed.extend_from_slice(peer_public);
        signed.extend_from_slice(peer_identifier);
        signed.extend_from_slice(our_public);
        peer_identity.verify(&signed, &signature).map_err(|_| {
            AirPlayError::PairVerifyRefused("receiver signature did not verify".to_owned())
        })
    }
}

/// ChaCha20-Poly1305 seal with a HAP-style 8-byte nonce label, zero-padded to 12 bytes.
pub fn seal(key: &[u8; 32], nonce_label: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = pad_nonce(nonce_label)?;
    cipher
        .encrypt(
            &Nonce::from(nonce),
            Payload {
                msg: plaintext,
                aad: &[],
            },
        )
        .map_err(|_| AirPlayError::Protocol("ChaCha20-Poly1305 seal failed".to_owned()))
}

/// ChaCha20-Poly1305 open, the inverse of [`seal`].
pub fn open(key: &[u8; 32], nonce_label: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = pad_nonce(nonce_label)?;
    cipher
        .decrypt(
            &Nonce::from(nonce),
            Payload {
                msg: ciphertext,
                aad: &[],
            },
        )
        .map_err(|_| AirPlayError::Protocol("ChaCha20-Poly1305 open failed".to_owned()))
}

/// HAP nonces are an 8-byte ASCII label right-aligned in a 12-byte field.
fn pad_nonce(label: &[u8]) -> Result<[u8; 12]> {
    if label.len() > 12 {
        return Err(AirPlayError::Protocol("nonce label is too long".to_owned()));
    }
    let mut nonce = [0u8; 12];
    nonce[12 - label.len()..].copy_from_slice(label);
    Ok(nonce)
}

/// Formats 16 random bytes as the uppercase UUID string a HAP pairing identifier takes; public for
/// Companion pairing.
pub fn uppercase_uuid(bytes: &[u8; 16]) -> String {
    let hex = hex::encode_upper(bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_parse_rejects_wrong_field_count() {
        let err = HapCredentials::parse("aa:bb:cc").unwrap_err();
        assert!(
            matches!(err, AirPlayError::Credentials(_)),
            "expected Credentials variant, got: {err:?}"
        );
    }

    #[test]
    fn credential_parse_rejects_non_hex() {
        let err = HapCredentials::parse("ZZZZ:bb:cc:dd").unwrap_err();
        assert!(
            matches!(err, AirPlayError::Credentials(_)),
            "expected Credentials variant, got: {err:?}"
        );
    }

    #[test]
    fn credential_parse_rejects_wrong_key_length() {
        // The first field is only 2 bytes rather than 32.
        let err = HapCredentials::parse("aabb:ccdd:eeff:0011").unwrap_err();
        assert!(
            matches!(err, AirPlayError::Credentials(_)),
            "expected Credentials variant, got: {err:?}"
        );
    }

    #[test]
    fn credential_round_trip() {
        let original = HapCredentials {
            device_public: [0xAA; 32],
            client_secret: [0xBB; 32],
            device_id: b"receiver".to_vec(),
            client_id: b"sender".to_vec(),
        };
        let storage = original.to_storage_string();
        let parsed = HapCredentials::parse(&storage).expect("round-trip parse");
        assert_eq!(parsed.device_public, original.device_public);
        assert_eq!(parsed.client_secret, original.client_secret);
        assert_eq!(parsed.device_id, original.device_id);
        assert_eq!(parsed.client_id, original.client_id);
    }

    #[test]
    fn uppercase_uuid_format() {
        let bytes = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        assert_eq!(
            uppercase_uuid(&bytes),
            "01234567-89AB-CDEF-FEDC-BA9876543210"
        );
    }

    #[test]
    fn constant_time_eq_same() {
        assert!(constant_time_eq(b"hello", b"hello"));
    }

    #[test]
    fn constant_time_eq_different() {
        assert!(!constant_time_eq(b"hello", b"world"));
    }

    #[test]
    fn constant_time_eq_different_lengths() {
        assert!(!constant_time_eq(b"short", b"longer"));
    }
}
