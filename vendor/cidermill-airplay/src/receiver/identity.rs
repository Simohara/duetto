//! Who the receiver says it is: its name, ids, key and feature word.

use ed25519_dalek::SigningKey;
use plist::Value;
use rand_core::CryptoRng;

use super::advertisement::STATUS_AUDIO_CABLE_ATTACHED;
use super::pairing::AccessoryIdentity;
use crate::Features;

/// The default advertised `model`; deliberately not an Apple model.
pub const DEFAULT_MODEL: &str = "AirPlayReceiver1,1";

/// The AirPlay version reported (`srcvers`, `sourceVersion`, `Server: AirTunes/…`). ASSUMED; a
/// sender may gate on it.
pub const SOURCE_VERSION: &str = "366.0";

/// `protovers`.
pub const PROTOCOL_VERSION: &str = "1.1";

/// Everything the receiver says about itself.
#[derive(Clone)]
#[non_exhaustive]
pub struct ReceiverIdentity {
    /// Friendly name, shown in a sender's picker.
    pub name: String,
    /// MAC-shaped device id (`deviceid`), upper case with colons.
    pub device_id: String,
    /// Pairing identity (`pi`): a UUID string, also the HAP accessory identifier.
    pub pairing_id: String,
    /// `model`.
    pub model: String,
    /// `srcvers`.
    pub source_version: String,
    /// The feature word: [`Features::MINIMAL_AUDIO`] unless the host sets its own.
    pub features: Features,
    /// `flags` / `statusFlags`, before [`super::ReceiverConfig::status_flags`] sets the PIN bit.
    pub status_flags: u32,
    /// Long-term Ed25519 key (`pk` is its public half).
    pub signing_key: SigningKey,
}

impl std::fmt::Debug for ReceiverIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReceiverIdentity")
            .field("name", &self.name)
            .field("device_id", &self.device_id)
            .field("pairing_id", &self.pairing_id)
            .field("features", &self.features)
            .finish_non_exhaustive()
    }
}

impl ReceiverIdentity {
    /// An identity with [`Features::MINIMAL_AUDIO`], [`DEFAULT_MODEL`] and [`SOURCE_VERSION`].
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        device_id: impl Into<String>,
        pairing_id: impl Into<String>,
        signing_key: SigningKey,
    ) -> Self {
        Self {
            name: name.into(),
            device_id: device_id.into(),
            pairing_id: pairing_id.into(),
            model: DEFAULT_MODEL.to_owned(),
            source_version: SOURCE_VERSION.to_owned(),
            features: Features::MINIMAL_AUDIO,
            status_flags: STATUS_AUDIO_CABLE_ATTACHED,
            signing_key,
        }
    }

    /// A random identity: device id, pairing id and key. Persist it: a sender files its pairing
    /// under `pi` and `pk`.
    pub fn generate(name: impl Into<String>, rng: &mut dyn CryptoRng) -> Self {
        let device_id = crate::util::random_mac(rng);
        let pairing_id = crate::util::uuid_v4(rng);
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        Self::new(name, device_id, pairing_id, SigningKey::from_bytes(&seed))
    }

    /// This identity with another feature word.
    #[must_use]
    pub fn with_features(mut self, features: Features) -> Self {
        self.features = features;
        self
    }

    /// This identity with another `model`.
    #[must_use]
    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.model = model.into();
        self
    }

    /// The HAP accessory identity pairing runs under.
    #[must_use]
    pub fn accessory(&self) -> AccessoryIdentity {
        AccessoryIdentity {
            identifier: self.pairing_id.as_bytes().to_vec(),
            signing_key: self.signing_key.clone(),
        }
    }

    /// `pk`: the Ed25519 public key.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }
}

/// The `qualifier` list of a `GET /info` body, empty if absent or malformed.
#[must_use]
pub fn info_qualifiers(body: &[u8]) -> Vec<String> {
    if body.is_empty() {
        return Vec::new();
    }
    crate::safe_plist::from_bytes(body)
        .ok()
        .as_ref()
        .and_then(Value::as_dictionary)
        .and_then(|d| d.get("qualifier"))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_string)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}
