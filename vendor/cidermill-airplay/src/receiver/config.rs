//! Receiver-wide configuration: who the receiver is, how senders pair, what it accepts. Built once
//! with [`ReceiverConfig::builder`] and shared by every connection.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use plist::Value;

use super::advertisement::{ReceiverAdvertisement, STATUS_PIN_REQUIRED};
use super::controllers::{ControllerStore, MemoryControllerStore};
use super::identity::{ReceiverIdentity, PROTOCOL_VERSION};
use super::pin::PinGate;
use crate::error::{AirPlayError, Result};
use crate::extension::ReceiverExtension;

/// Volume in dB until a sender sets one.
pub const DEFAULT_INITIAL_VOLUME: f64 = -20.0;

/// Live on/off switches read on every request, shared by clones. All off by default.
#[derive(Clone, Default)]
pub struct ReceiverSwitches(Arc<Switches>);

#[derive(Default)]
struct Switches {
    mirroring: AtomicBool,
    url_playback: AtomicBool,
    buffered_audio: AtomicBool,
    airplay1_audio: AtomicBool,
}

impl ReceiverSwitches {
    /// Answer a screen-mirroring stream `SETUP` (`type: 110`) on a pair-verified connection. Needs
    /// the `mirror` feature; 501 when off.
    #[must_use]
    pub fn mirroring(&self) -> bool {
        self.0.mirroring.load(Ordering::Relaxed)
    }

    /// See [`Self::mirroring`].
    pub fn set_mirroring(&self, on: bool) {
        self.0.mirroring.store(on, Ordering::Relaxed);
    }

    /// Answer URL video and photo pushes (`/play`, `/rate`, `/scrub`, `/stop`, `/playback-info`,
    /// `/photo`) on a pair-verified connection (403 on a transient one); 404 when off. Only the
    /// URL's scheme and credentials are checked; which hosts to fetch is the host's call.
    #[must_use]
    pub fn url_playback(&self) -> bool {
        self.0.url_playback.load(Ordering::Relaxed)
    }

    /// See [`Self::url_playback`].
    pub fn set_url_playback(&self, on: bool) {
        self.0.url_playback.store(on, Ordering::Relaxed);
    }

    /// Answer a buffered audio stream `SETUP` (`type: 103`) with an `shk` on a pair-verified
    /// connection (403 on a transient one); 501 when off. Needs a PTP follower.
    #[must_use]
    pub fn buffered_audio(&self) -> bool {
        self.0.buffered_audio.load(Ordering::Relaxed)
    }

    /// See [`Self::buffered_audio`].
    pub fn set_buffered_audio(&self, on: bool) {
        self.0.buffered_audio.store(on, Ordering::Relaxed);
    }

    /// Answer an AirPlay 1 sender in the clear: `ANNOUNCE` (an SDP with no key), then a `SETUP`
    /// with a `Transport` header opening one unencrypted realtime stream ([`crate::raop`]). Only
    /// while transient pairing is allowed too: such a sender cannot pair, so a receiver that asks
    /// for a PIN answers it 470 as before. Nothing authenticates its audio.
    #[must_use]
    pub fn airplay1_audio(&self) -> bool {
        self.0.airplay1_audio.load(Ordering::Relaxed)
    }

    /// See [`Self::airplay1_audio`].
    pub fn set_airplay1_audio(&self, on: bool) {
        self.0.airplay1_audio.store(on, Ordering::Relaxed);
    }
}

impl std::fmt::Debug for ReceiverSwitches {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReceiverSwitches")
            .field("mirroring", &self.mirroring())
            .field("url_playback", &self.url_playback())
            .field("buffered_audio", &self.buffered_audio())
            .field("airplay1_audio", &self.airplay1_audio())
            .finish()
    }
}

/// Receiver-wide configuration shared by every connection.
pub struct ReceiverConfig {
    identity: ReceiverIdentity,
    port: u16,
    allow_transient: bool,
    fixed_pin: Option<String>,
    pin_gate: Arc<PinGate>,
    initial_volume: f64,
    extension: Option<Arc<dyn ReceiverExtension>>,
    controllers: Arc<dyn ControllerStore>,
    switches: ReceiverSwitches,
    extra_txt: Vec<(String, String)>,
}

impl std::fmt::Debug for ReceiverConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReceiverConfig")
            .field("identity", &self.identity)
            .field("port", &self.port)
            .field("allow_transient", &self.allow_transient)
            .field("fixed_pin", &self.fixed_pin.as_ref().map(|_| "<set>"))
            .field("extension", &self.extension.is_some())
            .field("switches", &self.switches)
            .field("extra_txt", &self.extra_txt)
            .finish_non_exhaustive()
    }
}

impl ReceiverConfig {
    /// A builder for `identity` serving on control port `port`. PIN pairing only, random PINs,
    /// controllers in memory, every switch off.
    pub fn builder(identity: ReceiverIdentity, port: u16) -> ReceiverConfigBuilder {
        ReceiverConfigBuilder {
            config: Self {
                identity,
                port,
                allow_transient: false,
                fixed_pin: None,
                pin_gate: Arc::new(PinGate::new()),
                initial_volume: DEFAULT_INITIAL_VOLUME,
                extension: None,
                controllers: Arc::new(MemoryControllerStore::new()),
                switches: ReceiverSwitches::default(),
                extra_txt: Vec::new(),
            },
        }
    }

    /// Who the receiver is.
    #[must_use]
    pub fn identity(&self) -> &ReceiverIdentity {
        &self.identity
    }

    /// The control port the records point at.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Whether transient pair-setup (PIN `3939`, nothing stored) is accepted.
    #[must_use]
    pub fn allow_transient(&self) -> bool {
        self.allow_transient
    }

    /// The fixed PIN, when one replaces the random digits.
    #[must_use]
    pub fn fixed_pin(&self) -> Option<&str> {
        self.fixed_pin.as_deref()
    }

    /// The receiver's one current PIN and its limits.
    #[must_use]
    pub fn pin_gate(&self) -> &Arc<PinGate> {
        &self.pin_gate
    }

    /// Volume in dB (0 loudest, -144 mute) until a sender sets one.
    #[must_use]
    pub fn initial_volume(&self) -> f64 {
        self.initial_volume
    }

    /// The receiver extension, if any ([`crate::extension`]).
    #[must_use]
    pub fn extension(&self) -> Option<&Arc<dyn ReceiverExtension>> {
        self.extension.as_ref()
    }

    /// The paired controllers.
    #[must_use]
    pub fn controllers(&self) -> &Arc<dyn ControllerStore> {
        &self.controllers
    }

    /// The live switches; clone them to flip one later.
    #[must_use]
    pub fn switches(&self) -> &ReceiverSwitches {
        &self.switches
    }

    /// The advertised status word: the identity's, with [`STATUS_PIN_REQUIRED`] set when transient
    /// pairing is refused.
    #[must_use]
    pub fn status_flags(&self) -> u32 {
        let flags = self.identity.status_flags & !STATUS_PIN_REQUIRED;
        if self.allow_transient {
            flags
        } else {
            flags | STATUS_PIN_REQUIRED
        }
    }

    /// The `_airplay._tcp` and `_raop._tcp` records for this configuration.
    #[must_use]
    pub fn advertisement(&self) -> ReceiverAdvertisement {
        ReceiverAdvertisement::build(
            &self.identity,
            self.status_flags(),
            self.port,
            &self.extra_txt,
        )
    }

    /// The `GET /info` dictionary; a `qualifier` of `txtAirPlay` / `txtRAOP` adds that TXT record
    /// as DNS wire bytes.
    #[must_use]
    pub fn info_dictionary(&self, qualifiers: &[String], volume: f64) -> plist::Dictionary {
        let identity = &self.identity;
        let mut dict = plist::Dictionary::new();
        let s = |v: &str| Value::String(v.to_owned());
        dict.insert("name".into(), s(&identity.name));
        dict.insert("model".into(), s(&identity.model));
        dict.insert("sourceVersion".into(), s(&identity.source_version));
        dict.insert("deviceID".into(), s(&identity.device_id));
        dict.insert("macAddress".into(), s(&identity.device_id));
        dict.insert("protocolVersion".into(), s(PROTOCOL_VERSION));
        dict.insert(
            "features".into(),
            Value::Integer(identity.features.bits().into()),
        );
        dict.insert(
            "statusFlags".into(),
            Value::Integer(u64::from(self.status_flags()).into()),
        );
        dict.insert("pk".into(), Value::Data(identity.public_key().to_vec()));
        dict.insert("pi".into(), s(&identity.pairing_id));
        dict.insert("initialVolume".into(), Value::Real(volume));
        // Apple TV answers 4, HomePod 3; 3 is the speaker's.
        dict.insert("volumeControlType".into(), Value::Integer(3.into()));
        if qualifiers.is_empty() {
            return dict;
        }
        let advertisement = self.advertisement();
        for qualifier in qualifiers {
            let record = match qualifier.as_str() {
                "txtAirPlay" => &advertisement.airplay_txt,
                "txtRAOP" => &advertisement.raop_txt,
                _ => continue,
            };
            dict.insert(
                qualifier.clone(),
                Value::Data(ReceiverAdvertisement::txt_wire(record)),
            );
        }
        dict
    }

    /// [`Self::info_dictionary`] as a binary plist.
    ///
    /// # Errors
    ///
    /// The plist could not be encoded.
    pub fn info_body(&self, qualifiers: &[String], volume: f64) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        plist::to_writer_binary(
            &mut out,
            &Value::Dictionary(self.info_dictionary(qualifiers, volume)),
        )
        .map_err(|e| AirPlayError::Protocol(format!("could not encode /info: {e}")))?;
        Ok(out)
    }
}

/// Builds a [`ReceiverConfig`]; see [`ReceiverConfig::builder`].
#[derive(Debug)]
#[must_use]
pub struct ReceiverConfigBuilder {
    config: ReceiverConfig,
}

impl ReceiverConfigBuilder {
    /// Accept transient pair-setup: any sender on the network can play, nothing stored. Off by
    /// default; when off the records say a PIN is required.
    pub fn allow_transient(mut self, allow: bool) -> Self {
        self.config.allow_transient = allow;
        self
    }

    /// A fixed PIN instead of random digits (probes and tests; the gate's limits still apply).
    pub fn fixed_pin(mut self, pin: impl Into<String>) -> Self {
        self.config.fixed_pin = Some(pin.into());
        self
    }

    /// The PIN gate, to share one or run it on another clock. A new gate re-arms a locked receiver.
    pub fn pin_gate(mut self, gate: Arc<PinGate>) -> Self {
        self.config.pin_gate = gate;
        self
    }

    /// Volume in dB until a sender sets one ([`DEFAULT_INITIAL_VOLUME`] otherwise).
    pub fn initial_volume(mut self, volume: f64) -> Self {
        self.config.initial_volume = volume;
        self
    }

    /// A receiver extension ([`crate::extension`]). It does not change the advertised features.
    pub fn extension(mut self, extension: Arc<dyn ReceiverExtension>) -> Self {
        self.config.extension = Some(extension);
        self
    }

    /// Where paired controllers are kept ([`MemoryControllerStore`] otherwise).
    pub fn controllers(mut self, store: Arc<dyn ControllerStore>) -> Self {
        self.config.controllers = store;
        self
    }

    /// The initial state of [`ReceiverSwitches::mirroring`].
    pub fn mirroring(self, on: bool) -> Self {
        self.config.switches.set_mirroring(on);
        self
    }

    /// The initial state of [`ReceiverSwitches::url_playback`].
    pub fn url_playback(self, on: bool) -> Self {
        self.config.switches.set_url_playback(on);
        self
    }

    /// The initial state of [`ReceiverSwitches::buffered_audio`].
    pub fn buffered_audio(self, on: bool) -> Self {
        self.config.switches.set_buffered_audio(on);
        self
    }

    /// The initial state of [`ReceiverSwitches::airplay1_audio`].
    pub fn airplay1_audio(self, on: bool) -> Self {
        self.config.switches.set_airplay1_audio(on);
        self
    }

    /// An extra `key=value` at the end of the `_airplay._tcp` record (and `/info`'s `txtAirPlay`).
    pub fn extra_txt(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.config.extra_txt.push((key.into(), value.into()));
        self
    }

    /// The configuration, ready to share.
    pub fn build(self) -> Arc<ReceiverConfig> {
        Arc::new(self.config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn identity() -> ReceiverIdentity {
        ReceiverIdentity::generate("Kitchen", &mut StdRng::seed_from_u64(3))
    }

    fn txt<'a>(record: &'a [(String, String)], key: &str) -> Option<&'a str> {
        record
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    #[test]
    fn the_pin_required_bit_follows_the_pairing_choice() {
        let pin_only = ReceiverConfig::builder(identity(), 7000).build();
        let open = ReceiverConfig::builder(identity(), 7000)
            .allow_transient(true)
            .build();
        assert!(!pin_only.allow_transient(), "PIN pairing only by default");
        assert_ne!(pin_only.status_flags() & STATUS_PIN_REQUIRED, 0);
        assert_eq!(open.status_flags() & STATUS_PIN_REQUIRED, 0);
        for (config, flags) in [(&pin_only, "0x204"), (&open, "0x4")] {
            let ad = config.advertisement();
            assert_eq!(txt(&ad.airplay_txt, "flags"), Some(flags));
            assert_eq!(txt(&ad.raop_txt, "sf"), Some(flags));
            let info = config.info_dictionary(&[], -20.0);
            assert_eq!(
                info.get("statusFlags").and_then(Value::as_unsigned_integer),
                Some(u64::from(config.status_flags()))
            );
        }
    }

    #[test]
    fn extra_txt_ends_the_airplay_record_and_info_carries_it() {
        let config = ReceiverConfig::builder(identity(), 7000)
            .extra_txt("x", "1")
            .build();
        let ad = config.advertisement();
        assert_eq!(ad.airplay_txt.last(), Some(&("x".into(), "1".into())));
        assert_eq!(txt(&ad.raop_txt, "x"), None);
        let info = config.info_dictionary(&["txtAirPlay".into()], -20.0);
        assert_eq!(
            info.get("txtAirPlay").and_then(Value::as_data),
            Some(ReceiverAdvertisement::txt_wire(&ad.airplay_txt).as_slice())
        );
    }

    #[test]
    fn switches_are_shared_by_clones_and_start_from_the_builder() {
        let config = ReceiverConfig::builder(identity(), 7000)
            .url_playback(true)
            .build();
        let switches = config.switches().clone();
        assert!(switches.url_playback());
        assert!(!switches.mirroring());
        assert!(!switches.buffered_audio());
        switches.set_mirroring(true);
        switches.set_url_playback(false);
        assert!(config.switches().mirroring());
        assert!(!config.switches().url_playback());
    }
}
