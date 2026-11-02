//! Parsing a property list from a peer, bounded.
//!
//! [`plist::Value::from_reader`] builds a value of any depth, and dropping a deeply nested
//! [`plist::Value`] recurses once per level: a few hundred kilobytes of nested arrays parse, then
//! overflow the stack when the value is dropped. A binary plist can also point many references at
//! one shared collection, string or data object, so a small body can describe an exponentially
//! large value. Every plist that arrives from the network goes through [`from_bytes`] instead,
//! which walks the body first and refuses one nested deeper than [`MAX_DEPTH`], holding more values
//! than [`value_budget`] or more string and data bytes than [`payload_budget`], before anything is
//! built. A binary plist that contains itself is refused by the reader.

use std::cell::Cell;
use std::fmt;
use std::io::Cursor;

use plist::Value;
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};

use crate::error::{AirPlayError, Result};

/// The deepest nesting of arrays and dictionaries accepted: the root collection is depth 1.
///
/// Real `SETUP`, `/command`, `/info` and data-channel bodies nest well under ten levels; this
/// leaves room for any of them while keeping a dropped [`Value`]'s recursion trivial.
pub const MAX_DEPTH: usize = 64;

/// The most values (scalars and collections) accepted in any body, whatever its size.
pub const MAX_EVENTS: usize = 1 << 20;

/// The fewest values a body is allowed, however short it is ([`value_budget`]).
pub const MIN_EVENTS: usize = 4096;

/// The most string and data bytes, dictionary keys included, accepted in any body, whatever its
/// size.
///
/// Above the 16 MB post-pairing body cap ([`crate::rtsp::MAX_BODY_BYTES`]), so a body made of one
/// large `Data` value (artwork) always fits.
pub const MAX_PAYLOAD_BYTES: usize = 64 * 1024 * 1024;

/// The fewest string and data bytes a body is allowed, however short it is ([`payload_budget`]).
pub const MIN_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;

/// How many values a body of `body_len` bytes may hold: twice its length, at least [`MIN_EVENTS`]
/// and at most [`MAX_EVENTS`].
///
/// A binary plist spends at least one reference byte per value unless it shares a collection
/// between parents, and an XML or ASCII one several bytes, so a body that shares no collection
/// stays inside this.
#[must_use]
pub fn value_budget(body_len: usize) -> usize {
    body_len.saturating_mul(2).clamp(MIN_EVENTS, MAX_EVENTS)
}

/// How many string and data bytes (dictionary keys included) a body of `body_len` bytes may
/// expand to: four times its length, at least [`MIN_PAYLOAD_BYTES`] and at most
/// [`MAX_PAYLOAD_BYTES`].
///
/// A body that shares nothing carries each byte once; four times leaves room for a writer that
/// stores a repeated string once and refers to it from several places.
#[must_use]
pub fn payload_budget(body_len: usize) -> usize {
    body_len
        .saturating_mul(4)
        .clamp(MIN_PAYLOAD_BYTES, MAX_PAYLOAD_BYTES)
}

/// Parses a plist (binary, XML or ASCII) from untrusted bytes, refusing one nested deeper than
/// [`MAX_DEPTH`], holding more than [`value_budget`] values, or expanding to more than
/// [`payload_budget`] string and data bytes.
///
/// The body is walked once to check every bound, recursing no deeper than [`MAX_DEPTH`], keeping
/// nothing it reads and stopping at the first violation, and only then built as a [`Value`].
/// Errors with [`AirPlayError::Protocol`] for those and for a malformed body.
pub fn from_bytes(body: &[u8]) -> Result<Value> {
    parse(body, "plist refused")
}

/// [`from_bytes`], its error reading `"{what}: {why}"`.
pub(crate) fn parse(body: &[u8], what: &str) -> Result<Value> {
    build(body).map_err(|why| AirPlayError::Protocol(format!("{what}: {why}")))
}

fn build(body: &[u8]) -> std::result::Result<Value, String> {
    BUDGET.with(|budget| {
        budget.set(Budget {
            values_left: value_budget(body.len()),
            bytes_left: payload_budget(body.len()),
            ..Budget::default()
        });
    });
    let checked = plist::from_bytes::<Checked>(body);
    let budget = BUDGET.with(Cell::take);
    match budget.refusal {
        Some(Refusal::Depth) => return Err(format!("nested deeper than {MAX_DEPTH} levels")),
        Some(Refusal::Values) => {
            return Err(format!(
                "more than {} values in a {}-byte body",
                value_budget(body.len()),
                body.len()
            ))
        }
        Some(Refusal::Bytes) => {
            return Err(format!(
                "more than {} string and data bytes in a {}-byte body",
                payload_budget(body.len()),
                body.len()
            ))
        }
        None => {}
    }
    checked.map_err(|e| e.to_string())?;
    Value::from_reader(Cursor::new(body)).map_err(|e| e.to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refusal {
    Depth,
    Values,
    Bytes,
}

#[derive(Debug, Default, Clone, Copy)]
struct Budget {
    depth: usize,
    values_left: usize,
    bytes_left: usize,
    refusal: Option<Refusal>,
}

thread_local! {
    /// The walk's state. `plist::from_bytes` takes a type, not a seed, so the visitor keeps it
    /// here; [`build`] sets it before the walk and reads it after.
    static BUDGET: Cell<Budget> = const {
        Cell::new(Budget { depth: 0, values_left: 0, bytes_left: 0, refusal: None })
    };
}

/// A plist value walked and thrown away, counted against the budget.
struct Checked;

impl<'de> Deserialize<'de> for Checked {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        deserializer.deserialize_any(CheckedVisitor)
    }
}

struct CheckedVisitor;

/// Spends one value and `bytes` payload bytes; an error once either budget is gone.
fn spend<E: de::Error>(bytes: usize) -> std::result::Result<Checked, E> {
    BUDGET.with(|cell| {
        let mut budget = cell.get();
        let refusal = if budget.values_left == 0 {
            Some(Refusal::Values)
        } else if bytes > budget.bytes_left {
            Some(Refusal::Bytes)
        } else {
            budget.values_left -= 1;
            budget.bytes_left -= bytes;
            None
        };
        budget.refusal = budget.refusal.or(refusal);
        cell.set(budget);
        match refusal {
            Some(_) => Err(E::custom("over budget")),
            None => Ok(Checked),
        }
    })
}

/// Enters a collection; an error, before anything inside it is read, past [`MAX_DEPTH`].
fn enter<E: de::Error>() -> std::result::Result<(), E> {
    spend::<E>(0)?;
    BUDGET.with(|cell| {
        let mut budget = cell.get();
        budget.depth += 1;
        if budget.depth > MAX_DEPTH {
            budget.refusal = budget.refusal.or(Some(Refusal::Depth));
            cell.set(budget);
            return Err(E::custom("nested too deep"));
        }
        cell.set(budget);
        Ok(())
    })
}

fn leave() {
    BUDGET.with(|cell| {
        let mut budget = cell.get();
        budget.depth = budget.depth.saturating_sub(1);
        cell.set(budget);
    });
}

impl<'de> Visitor<'de> for CheckedVisitor {
    type Value = Checked;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a property list value")
    }

    fn visit_bool<E: de::Error>(self, _: bool) -> std::result::Result<Checked, E> {
        spend(0)
    }
    fn visit_i64<E: de::Error>(self, _: i64) -> std::result::Result<Checked, E> {
        spend(0)
    }
    fn visit_u64<E: de::Error>(self, _: u64) -> std::result::Result<Checked, E> {
        spend(0)
    }
    fn visit_f64<E: de::Error>(self, _: f64) -> std::result::Result<Checked, E> {
        spend(0)
    }
    // Strings (dictionary keys and dates among them) and data count their length; a copy the
    // reader made is dropped at once.
    fn visit_str<E: de::Error>(self, value: &str) -> std::result::Result<Checked, E> {
        spend(value.len())
    }
    fn visit_string<E: de::Error>(self, value: String) -> std::result::Result<Checked, E> {
        spend(value.len())
    }
    fn visit_bytes<E: de::Error>(self, value: &[u8]) -> std::result::Result<Checked, E> {
        spend(value.len())
    }
    fn visit_byte_buf<E: de::Error>(self, value: Vec<u8>) -> std::result::Result<Checked, E> {
        spend(value.len())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<Checked, A::Error> {
        enter()?;
        while seq.next_element::<Checked>()?.is_some() {}
        leave();
        Ok(Checked)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<Checked, A::Error> {
        enter()?;
        while map.next_entry::<Checked, Checked>()?.is_some() {}
        leave();
        Ok(Checked)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use plist::Dictionary;

    fn binary(value: &Value) -> Vec<u8> {
        let mut out = Vec::new();
        value.to_writer_binary(&mut out).unwrap();
        out
    }

    fn xml(value: &Value) -> Vec<u8> {
        let mut out = Vec::new();
        value.to_writer_xml(&mut out).unwrap();
        out
    }

    /// `depth` arrays, each holding the next, innermost empty. Built without a deep `Value`.
    pub(crate) fn nested_xml(depth: usize) -> Vec<u8> {
        let mut out = br#"<?xml version="1.0" encoding="UTF-8"?><plist version="1.0">"#.to_vec();
        out.extend(b"<array>".repeat(depth));
        out.extend(b"</array>".repeat(depth));
        out.extend(b"</plist>");
        out
    }

    fn realistic() -> Value {
        let mut stream = Dictionary::new();
        stream.insert("type".into(), Value::Integer(96.into()));
        stream.insert("ct".into(), Value::Integer(2.into()));
        stream.insert("shk".into(), Value::Data(vec![7; 32]));
        let mut root = Dictionary::new();
        root.insert("streams".into(), Value::Array(vec![stream.into()]));
        root.insert("rate".into(), Value::Real(1.0));
        root.insert("name".into(), Value::String("Sender".into()));
        root.insert("ok".into(), Value::Boolean(true));
        Value::Dictionary(root)
    }

    #[test]
    fn a_realistic_body_parses_the_same_as_the_plist_crate_parses_it() {
        let value = realistic();
        for body in [binary(&value), xml(&value)] {
            assert_eq!(from_bytes(&body).unwrap(), value);
            assert_eq!(Value::from_reader(Cursor::new(&body)).unwrap(), value);
        }
    }

    #[test]
    fn scalars_and_a_root_at_the_depth_limit_parse() {
        assert_eq!(
            from_bytes(&binary(&Value::Integer(5.into()))).unwrap(),
            Value::Integer(5.into())
        );
        assert!(from_bytes(&nested_xml(MAX_DEPTH)).is_ok());
    }

    #[test]
    fn a_deep_xml_body_is_refused_without_crashing() {
        let err = from_bytes(&nested_xml(MAX_DEPTH + 1)).unwrap_err();
        assert!(err.to_string().contains("deeper"), "{err}");
        assert!(from_bytes(&nested_xml(100_000)).is_err());
    }

    #[test]
    fn a_deep_binary_body_is_refused_without_crashing() {
        let err = from_bytes(&deep_binary(60_000)).unwrap_err();
        assert!(err.to_string().contains("deeper"), "{err}");
        assert!(from_bytes(&deep_binary(MAX_DEPTH)).is_ok());
    }

    #[test]
    fn a_binary_body_that_contains_itself_is_refused() {
        // One array whose only member is itself.
        let body = binary_plist(&[vec![0xA1, 0x00]], 0);
        assert!(from_bytes(&body).is_err());
    }

    #[test]
    fn a_binary_body_that_shares_collections_cannot_expand_without_bound() {
        // Object i is an array holding object i+1 twice; the last is an empty array. 40 levels of
        // doubling would expand to 2^40 events.
        let levels = 40u8;
        let mut objects: Vec<Vec<u8>> = (0..levels).map(|i| vec![0xA2, i + 1, i + 1]).collect();
        objects.push(vec![0xA0]);
        let err = from_bytes(&binary_plist(&objects, 0)).unwrap_err();
        assert!(err.to_string().contains("values"), "{err}");
    }

    #[test]
    fn junk_and_trailing_values_are_refused() {
        assert!(from_bytes(b"").is_err());
        assert!(from_bytes(b"bplist00").is_err());
        assert!(from_bytes(b"<plist><array>").is_err());
        assert!(from_bytes(b"<plist><dict><string>k</string></dict></plist>").is_err());
        assert!(from_bytes(b"<plist><dict><integer>1</integer><true/></dict></plist>").is_err());
    }

    /// An array of `count` references (two bytes each) to object `to`.
    fn refs(count: u16, to: u16) -> Vec<u8> {
        let mut object = vec![0xAF, 0x11];
        object.extend(count.to_be_bytes());
        for _ in 0..count {
            object.extend(to.to_be_bytes());
        }
        object
    }

    /// A `Data` object of `len` bytes.
    fn data(len: u32) -> Vec<u8> {
        let mut object = vec![0x4F, 0x12];
        object.extend(len.to_be_bytes());
        object.extend(std::iter::repeat_n(0x5A, len as usize));
        object
    }

    #[test]
    fn one_shared_data_object_cannot_expand_past_the_byte_budget() {
        // A 60 KB Data referred to 1000 times: a 62 KB body that would build 60 MB.
        let body = binary_plist_wide(&[refs(1000, 1), data(60 * 1024)], 2);
        assert!(body.len() < 64 * 1024);
        let started = std::time::Instant::now();
        let err = from_bytes(&body).unwrap_err();
        assert!(err.to_string().contains("string and data bytes"), "{err}");
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }

    #[test]
    fn a_shared_array_of_shared_data_is_refused() {
        // 1000 references to an array of 1000 references to one 1 KB Data: a 3 KB body that
        // would build a million values and a gigabyte.
        let body = binary_plist_wide(&[refs(1000, 1), refs(1000, 2), data(1024)], 2);
        assert!(body.len() < 8 * 1024);
        let started = std::time::Instant::now();
        let err = from_bytes(&body).unwrap_err();
        assert!(err.to_string().contains("in a 5090-byte body"), "{err}");
        // Without data, only the value count bounds it.
        let body = binary_plist_wide(&[refs(1000, 1), refs(1000, 2), vec![0x09]], 2);
        let err = from_bytes(&body).unwrap_err();
        assert!(err.to_string().contains("values"), "{err}");
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }

    #[test]
    fn one_large_data_value_is_accepted() {
        let mut dict = Dictionary::new();
        dict.insert("artwork".into(), Value::Data(vec![0xA5; 12 * 1024 * 1024]));
        let value = Value::Dictionary(dict);
        assert_eq!(from_bytes(&binary(&value)).unwrap(), value);
    }

    #[test]
    fn the_budgets_follow_the_body_size_between_their_bounds() {
        assert_eq!(value_budget(0), MIN_EVENTS);
        assert_eq!(value_budget(100_000), 200_000);
        assert_eq!(value_budget(usize::MAX), MAX_EVENTS);
        assert_eq!(payload_budget(0), MIN_PAYLOAD_BYTES);
        assert_eq!(payload_budget(10 * 1024 * 1024), 40 * 1024 * 1024);
        assert_eq!(payload_budget(usize::MAX), MAX_PAYLOAD_BYTES);
    }

    #[test]
    fn a_caller_names_what_it_was_reading_once() {
        let err = parse(b"junk", "SETUP body").unwrap_err();
        let AirPlayError::Protocol(message) = &err else {
            panic!("{err:?}")
        };
        assert!(message.starts_with("SETUP body: "), "{message}");
        assert!(!message.contains("protocol error"), "{message}");
    }

    /// A binary plist of `depth` nested one-element arrays, written by hand (one object each).
    pub(crate) fn deep_binary(depth: usize) -> Vec<u8> {
        // Object i is an array holding object i+1; the last is an empty array. Refs are 4 bytes.
        let mut objects: Vec<Vec<u8>> = (0..depth - 1)
            .map(|i| {
                let mut object = vec![0xA1];
                object.extend((i as u32 + 1).to_be_bytes());
                object
            })
            .collect();
        objects.push(vec![0xA0]);
        binary_plist_wide(&objects, 4)
    }

    fn binary_plist(objects: &[Vec<u8>], top: u64) -> Vec<u8> {
        assert_eq!(top, 0);
        binary_plist_wide(objects, 1)
    }

    /// `bplist00`, the objects, a 4-byte offset table and the trailer (top object 0).
    fn binary_plist_wide(objects: &[Vec<u8>], ref_size: u8) -> Vec<u8> {
        let mut out = b"bplist00".to_vec();
        let mut offsets = Vec::new();
        for object in objects {
            offsets.push(out.len() as u32);
            out.extend(object);
        }
        let table = out.len() as u64;
        for offset in offsets {
            out.extend(offset.to_be_bytes());
        }
        out.extend([0u8; 6]);
        out.push(4); // offset size
        out.push(ref_size);
        out.extend((objects.len() as u64).to_be_bytes());
        out.extend(0u64.to_be_bytes()); // top object
        out.extend(table.to_be_bytes());
        out
    }
}
