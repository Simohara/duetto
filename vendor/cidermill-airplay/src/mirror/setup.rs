//! The control-channel half of mirroring: the session `SETUP` key marker and the `type: 110`
//! stream `SETUP` and its reply.
//!
//! A session `SETUP` carries `isScreenMirroringSession` plus `cidermillMirror` (key from the
//! pairing) or `ekey` + `eiv` (an Apple sender's wrapped key). A stream `SETUP` carries
//! `streams: [{type: 110, streamConnectionID}]` and is answered with `dataPort`.
//! `streamConnectionID` is read signed or unsigned; [`draw_stream_connection_id`] stays where both
//! agree.

use plist::{Dictionary, Value};
use rand_core::CryptoRng;

use crate::error::{AirPlayError, Result};

use super::STREAM_TYPE;

/// Session `SETUP` key: the session is a mirroring one (Apple senders write it).
pub const IS_SCREEN_MIRRORING_SESSION: &str = "isScreenMirroringSession";

/// Session `SETUP` key: the sender derives the base key from the pairing
/// ([`super::key::MirrorKey::from_pairing`]); its value is the derivation's version.
pub const PAIRING_KEYED_MARKER: &str = "cidermillMirror";

/// The derivation version this crate writes and reads.
pub const PAIRING_KEYED_VERSION: u64 = 1;

/// Session `SETUP` key of a wrapped base key. Never unwrapped here; handed opaque to
/// [`crate::extension::ExtensionSession::unwrap_session_key`].
pub const WRAPPED_KEY: &str = "ekey";

/// Session `SETUP` key that travels with [`WRAPPED_KEY`]: the IV for realtime audio.
pub const WRAPPED_KEY_IV: &str = "eiv";

/// Stream key: the stream's id.
pub const STREAM_CONNECTION_ID: &str = "streamConnectionID";

/// How a session `SETUP` says the mirroring key will be agreed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MirrorMarker {
    /// `cidermillMirror` with this version, and no `ekey`.
    PairingKeyed {
        /// The version.
        version: u64,
    },
    /// `ekey` and no `cidermillMirror`: the key is wrapped (a receiver extension may unwrap it,
    /// [`crate::extension`]).
    WrappedKey,
    /// Both: contradictory.
    Both,
    /// Neither: unencrypted, never accepted.
    Neither,
}

impl MirrorMarker {
    /// Reads a session `SETUP` body's dictionary.
    #[must_use]
    pub fn of_session(dict: &Dictionary) -> Self {
        let version = dict.get(PAIRING_KEYED_MARKER).and_then(integer);
        let wrapped = dict.contains_key(WRAPPED_KEY);
        match (version, wrapped) {
            (Some(version), false) => Self::PairingKeyed { version },
            (None, true) => Self::WrappedKey,
            (Some(_), true) => Self::Both,
            (None, false) => Self::Neither,
        }
    }

    /// The keys a cidermill-airplay sender adds to its session `SETUP`.
    pub fn write_pairing_keyed(dict: &mut Dictionary) {
        dict.insert(IS_SCREEN_MIRRORING_SESSION.into(), Value::Boolean(true));
        dict.insert(
            PAIRING_KEYED_MARKER.into(),
            Value::Integer(PAIRING_KEYED_VERSION.into()),
        );
    }
}

/// A plist integer read as u64, signed or unsigned (negative values reinterpreted).
#[must_use]
pub fn integer(value: &Value) -> Option<u64> {
    let integer = value.as_signed_integer().map(|i| i.cast_unsigned());
    value.as_unsigned_integer().or(integer)
}

/// A fresh `streamConnectionID`: uniform in 1…2^63 − 1.
pub fn draw_stream_connection_id(rng: &mut dyn CryptoRng) -> u64 {
    loop {
        let id = rng.next_u64() >> 1;
        if id != 0 {
            return id;
        }
    }
}

/// The `type: 110` entry of a stream `SETUP`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MirrorStreamSetup {
    /// `streamConnectionID`.
    pub stream_connection_id: u64,
}

impl MirrorStreamSetup {
    /// The entry for the request's `streams` array; ids up to `i64::MAX` are written signed.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut entry = Dictionary::new();
        entry.insert("type".into(), Value::Integer(STREAM_TYPE.into()));
        let id = i64::try_from(self.stream_connection_id).map_or_else(
            |_| Value::Integer(self.stream_connection_id.into()),
            |signed| Value::Integer(signed.into()),
        );
        entry.insert(STREAM_CONNECTION_ID.into(), id);
        Value::Dictionary(entry)
    }

    /// The whole request body: `{streams: [entry]}`, a binary plist.
    ///
    /// # Errors
    ///
    /// The plist writer failing.
    pub fn to_body(&self) -> Result<Vec<u8>> {
        let mut body = Dictionary::new();
        body.insert("streams".into(), Value::Array(vec![self.to_value()]));
        binary(&body)
    }

    /// Reads a `type: 110` entry (the receiver's side).
    ///
    /// # Errors
    ///
    /// Not `type: 110`, or no non-zero `streamConnectionID`.
    pub fn from_entry(entry: &Dictionary) -> Result<Self> {
        if entry.get("type").and_then(integer) != Some(STREAM_TYPE) {
            return Err(AirPlayError::Protocol(
                "not a type 110 stream SETUP".to_owned(),
            ));
        }
        let id = entry
            .get(STREAM_CONNECTION_ID)
            .and_then(integer)
            .filter(|id| *id != 0)
            .ok_or_else(|| {
                AirPlayError::Protocol("type 110 stream SETUP has no streamConnectionID".to_owned())
            })?;
        Ok(Self {
            stream_connection_id: id,
        })
    }
}

/// The receiver's answer to a `type: 110` stream `SETUP`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MirrorStreamReply {
    /// The TCP port the sender connects to.
    pub data_port: u16,
}

impl MirrorStreamReply {
    /// The reply's `streams` entry.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut entry = Dictionary::new();
        entry.insert("type".into(), Value::Integer(STREAM_TYPE.into()));
        entry.insert(
            "dataPort".into(),
            Value::Integer(u64::from(self.data_port).into()),
        );
        Value::Dictionary(entry)
    }

    /// Reads the reply body (the sender's side): `streams[0]` must be `type: 110` with a port.
    ///
    /// # Errors
    ///
    /// Not a plist, no such entry, or a port out of range.
    pub fn parse(body: &[u8]) -> Result<Self> {
        let value = crate::safe_plist::parse(body, "mirror SETUP reply")?;
        let entry = value
            .as_dictionary()
            .and_then(|d| d.get("streams"))
            .and_then(Value::as_array)
            .and_then(|s| s.first())
            .and_then(Value::as_dictionary)
            .ok_or_else(|| AirPlayError::Protocol("mirror SETUP reply has no stream".to_owned()))?;
        if entry.get("type").and_then(integer) != Some(STREAM_TYPE) {
            return Err(AirPlayError::Protocol(
                "mirror SETUP reply is not type 110".to_owned(),
            ));
        }
        let port = entry
            .get("dataPort")
            .and_then(integer)
            .and_then(|p| u16::try_from(p).ok())
            .filter(|p| *p != 0)
            .ok_or_else(|| {
                AirPlayError::Protocol("mirror SETUP reply has no dataPort".to_owned())
            })?;
        Ok(Self { data_port: port })
    }
}

/// The `TEARDOWN` body that ends the mirror stream and keeps the session:
/// `{streams: [{type: 110}]}`.
///
/// # Errors
///
/// The plist writer failing.
pub fn teardown_body() -> Result<Vec<u8>> {
    let mut entry = Dictionary::new();
    entry.insert("type".into(), Value::Integer(STREAM_TYPE.into()));
    let mut body = Dictionary::new();
    body.insert(
        "streams".into(),
        Value::Array(vec![Value::Dictionary(entry)]),
    );
    binary(&body)
}

fn binary(dict: &Dictionary) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    plist::to_writer_binary(&mut out, dict)
        .map_err(|e| AirPlayError::Protocol(format!("plist: {e}")))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stream_teardown_names_only_the_mirror_type() {
        let body = teardown_body().unwrap();
        let value = Value::from_reader(std::io::Cursor::new(&body)).unwrap();
        let streams = value.as_dictionary().unwrap()["streams"]
            .as_array()
            .unwrap();
        assert_eq!(streams.len(), 1);
        let entry = streams[0].as_dictionary().unwrap();
        assert_eq!(entry.len(), 1);
        assert_eq!(entry.get("type").and_then(integer), Some(STREAM_TYPE));
    }

    fn dict(pairs: &[(&str, Value)]) -> Dictionary {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.clone()))
            .collect()
    }

    #[test]
    fn a_session_setup_is_classified_by_its_key_markers() {
        let mut keyed = Dictionary::new();
        MirrorMarker::write_pairing_keyed(&mut keyed);
        assert_eq!(
            MirrorMarker::of_session(&keyed),
            MirrorMarker::PairingKeyed { version: 1 }
        );
        let wrapped = dict(&[
            ("ekey", Value::Data(vec![0; 72])),
            ("eiv", Value::Data(vec![0; 16])),
        ]);
        assert_eq!(MirrorMarker::of_session(&wrapped), MirrorMarker::WrappedKey);
        let mut both = wrapped.clone();
        MirrorMarker::write_pairing_keyed(&mut both);
        assert_eq!(MirrorMarker::of_session(&both), MirrorMarker::Both);
        assert_eq!(
            MirrorMarker::of_session(&Dictionary::new()),
            MirrorMarker::Neither
        );
        let not_a_number = dict(&[("cidermillMirror", Value::String("1".into()))]);
        assert_eq!(
            MirrorMarker::of_session(&not_a_number),
            MirrorMarker::Neither
        );
    }

    #[test]
    fn a_stream_id_reads_the_same_signed_or_unsigned() {
        for written in [Value::Integer(42i64.into()), Value::Integer(42u64.into())] {
            let entry = dict(&[
                ("type", Value::Integer(110u64.into())),
                ("streamConnectionID", written),
            ]);
            assert_eq!(
                MirrorStreamSetup::from_entry(&entry)
                    .unwrap()
                    .stream_connection_id,
                42
            );
        }
        let negative = dict(&[
            ("type", Value::Integer(110u64.into())),
            ("streamConnectionID", Value::Integer((-1i64).into())),
        ]);
        assert_eq!(
            MirrorStreamSetup::from_entry(&negative)
                .unwrap()
                .stream_connection_id,
            u64::MAX
        );
        let large = dict(&[
            ("type", Value::Integer(110u64.into())),
            ("streamConnectionID", Value::Integer(u64::MAX.into())),
        ]);
        assert_eq!(
            MirrorStreamSetup::from_entry(&large)
                .unwrap()
                .stream_connection_id,
            u64::MAX
        );
        for bad in [
            dict(&[
                ("type", Value::Integer(96u64.into())),
                ("streamConnectionID", Value::Integer(1u64.into())),
            ]),
            dict(&[("type", Value::Integer(110u64.into()))]),
            dict(&[
                ("type", Value::Integer(110u64.into())),
                ("streamConnectionID", Value::Integer(0u64.into())),
            ]),
        ] {
            assert!(MirrorStreamSetup::from_entry(&bad).is_err());
        }
    }

    /// Counts up from a start value, one `u64` per draw.
    struct StepRng(u64);

    impl rand_core::TryRng for StepRng {
        type Error = rand_core::Infallible;

        fn try_next_u32(&mut self) -> std::result::Result<u32, Self::Error> {
            self.try_next_u64().map(|value| value as u32)
        }

        fn try_next_u64(&mut self) -> std::result::Result<u64, Self::Error> {
            let value = self.0;
            self.0 = value.wrapping_add(1);
            Ok(value)
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> std::result::Result<(), Self::Error> {
            for chunk in dst.chunks_mut(8) {
                let value = self.try_next_u64()?.to_le_bytes();
                chunk.copy_from_slice(&value[..chunk.len()]);
            }
            Ok(())
        }
    }

    impl rand_core::TryCryptoRng for StepRng {}

    #[test]
    fn drawn_ids_are_positive_in_both_readings_and_round_trip() {
        let mut rng = StepRng(u64::MAX);
        let id = draw_stream_connection_id(&mut rng);
        assert!(id >= 1 && id <= i64::MAX.cast_unsigned());
        let mut zeros = StepRng(0);
        assert_eq!(draw_stream_connection_id(&mut zeros), 1);
        let setup = MirrorStreamSetup {
            stream_connection_id: id,
        };
        let body = setup.to_body().unwrap();
        let value = Value::from_reader(std::io::Cursor::new(&body)).unwrap();
        let entry = value.as_dictionary().unwrap()["streams"]
            .as_array()
            .unwrap()[0]
            .as_dictionary()
            .unwrap()
            .clone();
        assert_eq!(MirrorStreamSetup::from_entry(&entry).unwrap(), setup);
    }

    #[test]
    fn the_reply_round_trips_and_a_bad_one_is_refused() {
        let reply = MirrorStreamReply { data_port: 7100 };
        let mut body = Dictionary::new();
        body.insert("streams".into(), Value::Array(vec![reply.to_value()]));
        assert_eq!(
            MirrorStreamReply::parse(&binary(&body).unwrap()).unwrap(),
            reply
        );
        assert!(MirrorStreamReply::parse(b"garbage").is_err());
        let mut no_port = Dictionary::new();
        no_port.insert("type".into(), Value::Integer(110u64.into()));
        let mut body = Dictionary::new();
        body.insert(
            "streams".into(),
            Value::Array(vec![Value::Dictionary(no_port)]),
        );
        assert!(MirrorStreamReply::parse(&binary(&body).unwrap()).is_err());
    }
}
