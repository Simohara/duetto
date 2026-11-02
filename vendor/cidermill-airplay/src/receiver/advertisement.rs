//! What a receiver puts in its `_airplay._tcp` and `_raop._tcp` records, as data. The records carry
//! the identity's feature word ([`crate::Features`]); the layout follows captured Apple TV and
//! HomePod records, minus what this crate cannot claim.

/// `statusFlags` bit 2, "audio cable attached".
pub const STATUS_AUDIO_CABLE_ATTACHED: u32 = 1 << 2;

/// `statusFlags` bit 9, "needs PIN to pair": set when PIN pair-setup is required rather than
/// transient. ASSUMED: no Apple sender has been observed reading it.
pub const STATUS_PIN_REQUIRED: u32 = 1 << 9;

/// `_raop` `cn`: the codecs we decode — 0 PCM, 1 ALAC.
pub const RAOP_CODECS: &str = "0,1";
/// `_raop` `et`: encryption types, 0 only.
pub const RAOP_ENCRYPTION_TYPES: &str = "0";
/// `_raop` `md`: metadata types: text, artwork, progress.
pub const RAOP_METADATA_TYPES: &str = "0,1,2";
/// `_raop` `tp`: transport.
pub const RAOP_TRANSPORT: &str = "UDP";
/// `_raop` `vn`.
pub const RAOP_VERSION: &str = "65537";

/// The longest DNS-SD instance name, in UTF-8 bytes (one DNS label, RFC 6763 §4.1.1).
pub const MAX_INSTANCE_BYTES: usize = 63;

/// Bytes kept free in each instance name for an mDNS conflict rename (` (2)` … ` (99)`).
pub const INSTANCE_RENAME_ROOM: usize = 5;

/// The longest instance name produced: [`MAX_INSTANCE_BYTES`] less [`INSTANCE_RENAME_ROOM`].
pub const INSTANCE_NAME_BYTES: usize = MAX_INSTANCE_BYTES - INSTANCE_RENAME_ROOM;

/// `name` cut to at most `max` bytes on a character boundary.
#[must_use]
pub fn truncate_utf8(name: &str, max: usize) -> &str {
    if name.len() <= max {
        return name;
    }
    let mut end = max;
    while !name.is_char_boundary(end) {
        end -= 1;
    }
    &name[..end]
}

/// The two records, ready for an mDNS responder.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ReceiverAdvertisement {
    /// `_airplay._tcp` instance name: the friendly name, cut to [`INSTANCE_NAME_BYTES`].
    pub airplay_instance: String,
    /// `_raop._tcp` instance name: `AABBCCDDEEFF@Name`, cut to fit [`INSTANCE_NAME_BYTES`].
    pub raop_instance: String,
    /// The TCP port both records point at.
    pub port: u16,
    /// `_airplay._tcp` TXT, in order.
    pub airplay_txt: Vec<(String, String)>,
    /// `_raop._tcp` TXT, in order.
    pub raop_txt: Vec<(String, String)>,
}

impl ReceiverAdvertisement {
    /// Both records; [`super::ReceiverConfig::advertisement`] is the public way in.
    pub(crate) fn build(
        identity: &super::ReceiverIdentity,
        status_flags: u32,
        port: u16,
        extra_txt: &[(String, String)],
    ) -> Self {
        let features = identity.features.to_txt();
        let flags = format!("0x{status_flags:X}");
        let pk = hex::encode(identity.public_key());
        let pair = |k: &str, v: &str| (k.to_owned(), v.to_owned());
        let mut airplay_txt = vec![
            pair("acl", "0"),
            pair("deviceid", &identity.device_id),
            pair("features", &features),
            pair("flags", &flags),
            pair("gcgl", "0"),
            pair("gid", &identity.pairing_id),
            pair("igl", "1"),
            pair("model", &identity.model),
            pair("pi", &identity.pairing_id),
            pair("pk", &pk),
            pair("protovers", super::identity::PROTOCOL_VERSION),
            pair("srcvers", &identity.source_version),
        ];
        airplay_txt.extend_from_slice(extra_txt);
        let raop_txt = vec![
            pair("am", &identity.model),
            pair("cn", RAOP_CODECS),
            pair("da", "true"),
            pair("et", RAOP_ENCRYPTION_TYPES),
            pair("ft", &features),
            pair("md", RAOP_METADATA_TYPES),
            pair("pk", &pk),
            pair("sf", &flags),
            pair("tp", RAOP_TRANSPORT),
            pair("vn", RAOP_VERSION),
            pair("vs", &identity.source_version),
        ];
        let raop_prefix = format!("{}@", identity.device_id.replace(':', ""));
        let raop_room = INSTANCE_NAME_BYTES.saturating_sub(raop_prefix.len());
        Self {
            airplay_instance: truncate_utf8(&identity.name, INSTANCE_NAME_BYTES).to_owned(),
            raop_instance: format!("{raop_prefix}{}", truncate_utf8(&identity.name, raop_room)),
            port,
            airplay_txt,
            raop_txt,
        }
    }

    /// A TXT record as DNS wire bytes (RFC 6763 §6); pairs over 255 bytes are truncated.
    #[must_use]
    pub fn txt_wire(pairs: &[(String, String)]) -> Vec<u8> {
        let mut out = Vec::new();
        for (key, value) in pairs {
            let mut item = format!("{key}={value}").into_bytes();
            item.truncate(255);
            out.push(u8::try_from(item.len()).unwrap_or(255));
            out.extend_from_slice(&item);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Features;

    #[test]
    fn the_records_advertise_whatever_word_the_identity_carries() {
        // Both records carry the identity's feature word and nothing else changes.
        let base =
            crate::receiver::ReceiverIdentity::generate("Kitchen".to_owned(), &mut crate::OsRng);
        let txt = |features: Option<Features>| {
            let mut identity = base.clone();
            if let Some(word) = features {
                identity.features = word;
            }
            let ad = ReceiverAdvertisement::build(&identity, identity.status_flags, 7000, &[]);
            let get = |txt: &[(String, String)], key: &str| {
                txt.iter().find(|(k, _)| k == key).unwrap().1.clone()
            };
            (
                get(&ad.airplay_txt, "features"),
                get(&ad.raop_txt, "ft"),
                ad,
            )
        };
        let chosen = Features::MINIMAL_AUDIO | Features::AUTHENTICATION_4;
        let (features, ft, with) = txt(Some(chosen));
        assert_eq!(features, chosen.to_txt());
        assert_eq!(ft, chosen.to_txt());
        let (features, ft, without) = txt(None);
        assert_eq!(features, Features::MINIMAL_AUDIO.to_txt());
        assert_eq!(ft, Features::MINIMAL_AUDIO.to_txt());
        let strip = |ad: &ReceiverAdvertisement| {
            let keep = |t: &[(String, String)]| {
                t.iter()
                    .filter(|(k, _)| k != "features" && k != "ft")
                    .cloned()
                    .collect::<Vec<_>>()
            };
            (keep(&ad.airplay_txt), keep(&ad.raop_txt))
        };
        assert_eq!(strip(&with), strip(&without));
    }

    #[test]
    fn a_name_that_fits_is_advertised_as_it_is() {
        let identity =
            crate::receiver::ReceiverIdentity::generate("Kitchen".to_owned(), &mut crate::OsRng);
        let ad = ReceiverAdvertisement::build(&identity, identity.status_flags, 7000, &[]);
        assert_eq!(ad.airplay_instance, "Kitchen");
        assert_eq!(
            ad.raop_instance,
            format!("{}@Kitchen", identity.device_id.replace(':', ""))
        );
    }

    #[test]
    fn instance_names_fit_one_dns_label_and_are_cut_between_characters() {
        for unit in ["a", "é", "音", "🍎"] {
            let name = unit.repeat(60);
            let identity =
                crate::receiver::ReceiverIdentity::generate(name.clone(), &mut crate::OsRng);
            let ad = ReceiverAdvertisement::build(&identity, identity.status_flags, 7000, &[]);
            for instance in [&ad.airplay_instance, &ad.raop_instance] {
                assert!(instance.len() <= INSTANCE_NAME_BYTES, "{unit}: {instance}");
                let renamed = format!("{instance} (99)");
                assert!(
                    renamed.len() <= MAX_INSTANCE_BYTES,
                    "room for a conflict rename"
                );
                assert!(!instance.is_empty());
            }
            let kept = ad.raop_instance.split_once('@').unwrap().1;
            assert!(name.starts_with(kept), "a prefix of whole characters");
            assert!(name.starts_with(ad.airplay_instance.as_str()));
            assert!(
                ad.airplay_instance.len() + unit.len() > INSTANCE_NAME_BYTES
                    || ad.airplay_instance == name
            );
            assert!(ad.raop_instance.len() + unit.len() > INSTANCE_NAME_BYTES);
        }
        let long = "x".repeat(80);
        let identity = crate::receiver::ReceiverIdentity::generate(long.clone(), &mut crate::OsRng);
        let ad = ReceiverAdvertisement::build(&identity, identity.status_flags, 7000, &[]);
        assert_eq!(ad.airplay_instance.len(), INSTANCE_NAME_BYTES);
        assert_eq!(identity.name, long, "what /info says is untouched");
    }

    #[test]
    fn truncation_never_splits_a_character() {
        assert_eq!(truncate_utf8("héllo", 2), "h");
        assert_eq!(truncate_utf8("héllo", 3), "hé");
        assert_eq!(truncate_utf8("🍎🍎", 7), "🍎");
        assert_eq!(truncate_utf8("🍎", 3), "");
        assert_eq!(truncate_utf8("abc", 63), "abc");
    }

    #[test]
    fn txt_wire_is_length_prefixed() {
        let wire = ReceiverAdvertisement::txt_wire(&[("a".into(), "bc".into())]);
        assert_eq!(wire, b"\x04a=bc");
    }
}
