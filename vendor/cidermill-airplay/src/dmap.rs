//! DMAP/DAAP encoding for outgoing now-playing metadata, and decoding for a receiver.
//!
//! A sender pushes track metadata as `application/x-dmap-tagged`, artwork as a raw image body and
//! playback progress as a `text/parameters` line, all via `SET_PARAMETER`. This module builds and
//! reads those bodies; it opens no socket. Fold [`NowPlaying::encode`], [`METADATA_CONTENT_TYPE`]
//! and [`MediaPosition::headers`] into an [`crate::rtsp::Request`].
//!
//! Layout: pyatv 0.18.0 `pyatv.protocols.dmap.tags` (`tests/dmap_pyatv_vectors.rs`). A tag carries
//! no type on the wire, so [`NowPlaying::decode`] reads only the codes written here and skips the
//! rest by length. `genre`, `track_number`, `disc_number` and `duration` are not sent by pyatv;
//! their codes are assumed from other DAAP implementations and unconfirmed on a receiver.

/// Raw DMAP tag primitives: a 4-byte ASCII code, a 4-byte big-endian length, then the payload.
///
/// Codes are `[u8; 4]` so a wrong-length code cannot be passed.
pub mod tag {
    /// Writes a DMAP tag with a raw byte payload (a container when the payload is further tags).
    ///
    /// A payload longer than [`u32::MAX`] bytes is truncated so the length prefix always matches.
    #[must_use]
    pub fn raw(code: [u8; 4], payload: &[u8]) -> Vec<u8> {
        let len = payload.len().min(u32::MAX as usize);
        let payload = &payload[..len];
        let mut out = Vec::with_capacity(8 + len);
        out.extend_from_slice(&code);
        #[allow(clippy::cast_possible_truncation)] // len is capped to u32::MAX just above.
        out.extend_from_slice(&(len as u32).to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    /// Writes a DMAP tag with UTF-8 string data (the prefix is the byte length).
    ///
    /// A value over [`u32::MAX`] bytes is truncated on a `char` boundary.
    #[must_use]
    pub fn string(code: [u8; 4], value: &str) -> Vec<u8> {
        let mut end = value.len().min(u32::MAX as usize);
        while end > 0 && !value.is_char_boundary(end) {
            end -= 1;
        }
        raw(code, &value.as_bytes()[..end])
    }

    /// Writes a DMAP tag whose payload is a concatenation of further tags; identical to [`raw`].
    #[must_use]
    pub fn container(code: [u8; 4], payload: &[u8]) -> Vec<u8> {
        raw(code, payload)
    }

    /// Writes a DMAP tag with 8-bit unsigned data.
    #[must_use]
    pub fn u8(code: [u8; 4], value: u8) -> Vec<u8> {
        raw(code, &value.to_be_bytes())
    }

    /// Writes a DMAP tag with 16-bit big-endian unsigned data.
    #[must_use]
    pub fn u16(code: [u8; 4], value: u16) -> Vec<u8> {
        raw(code, &value.to_be_bytes())
    }

    /// Writes a DMAP tag with 32-bit big-endian unsigned data.
    #[must_use]
    pub fn u32(code: [u8; 4], value: u32) -> Vec<u8> {
        raw(code, &value.to_be_bytes())
    }

    /// Writes a DMAP tag with 64-bit big-endian unsigned data.
    #[must_use]
    pub fn u64(code: [u8; 4], value: u64) -> Vec<u8> {
        raw(code, &value.to_be_bytes())
    }
}

/// DAAP/DMAP field codes this module writes. Observed means pyatv 0.18.0 sends it; assumed means
/// the code comes from another DAAP implementation.
pub mod codes {
    /// `dmap.listingitem` — the container a metadata `SET_PARAMETER` body is wrapped in.
    /// OBSERVED.
    pub const LISTING_ITEM: [u8; 4] = *b"mlit";
    /// `dmap.itemname` — track title. OBSERVED.
    pub const TITLE: [u8; 4] = *b"minm";
    /// `daap.songartist`. OBSERVED.
    pub const ARTIST: [u8; 4] = *b"asar";
    /// `daap.songalbum`. OBSERVED.
    pub const ALBUM: [u8; 4] = *b"asal";
    /// `daap.songgenre`. Assumed.
    pub const GENRE: [u8; 4] = *b"asgn";
    /// `daap.songtracknumber`, 16-bit. Assumed.
    pub const TRACK_NUMBER: [u8; 4] = *b"astn";
    /// `daap.songdiscnumber`, 16-bit. Assumed.
    pub const DISC_NUMBER: [u8; 4] = *b"asdn";
    /// `daap.songtime`, milliseconds, 32-bit. A real DAAP code; pyatv's metadata push never sends
    /// it.
    pub const SONG_TIME_MS: [u8; 4] = *b"astm";
}

/// `Content-Type` for [`NowPlaying::encode`]'s body. Observed (pyatv).
pub const METADATA_CONTENT_TYPE: &str = "application/x-dmap-tagged";

/// `Content-Type` for [`progress_body`]. Observed (pyatv).
pub const PROGRESS_CONTENT_TYPE: &str = "text/parameters";

/// Track metadata to push as a `SET_PARAMETER` body ([`NowPlaying::encode`]).
///
/// `title`/`artist`/`album` match what pyatv sends; the other fields are assumed (see module docs)
/// and a receiver that ignores them should skip them. `#[non_exhaustive]`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct NowPlaying {
    /// Track title (`dmap.itemname`/`minm`).
    pub title: Option<String>,
    /// Track artist (`daap.songartist`/`asar`).
    pub artist: Option<String>,
    /// Album title (`daap.songalbum`/`asal`).
    pub album: Option<String>,
    /// Genre (`daap.songgenre`/`asgn`). Assumed code.
    pub genre: Option<String>,
    /// 1-based track number (`daap.songtracknumber`/`astn`). ASSUMED code.
    pub track_number: Option<u16>,
    /// 1-based disc number (`daap.songdiscnumber`/`asdn`). ASSUMED code.
    pub disc_number: Option<u16>,
    /// Duration in milliseconds (`daap.songtime`/`astm`), clamped to [`u32::MAX`].
    pub duration_ms: Option<u32>,
}

impl NowPlaying {
    /// Encodes this as the `mlit`-wrapped metadata body ([`METADATA_CONTENT_TYPE`]).
    ///
    /// A `None` or empty field is omitted. Order is title, album, artist, then the additions.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        if let Some(title) = non_empty(&self.title) {
            payload.extend(tag::string(codes::TITLE, title));
        }
        if let Some(album) = non_empty(&self.album) {
            payload.extend(tag::string(codes::ALBUM, album));
        }
        if let Some(artist) = non_empty(&self.artist) {
            payload.extend(tag::string(codes::ARTIST, artist));
        }
        if let Some(genre) = non_empty(&self.genre) {
            payload.extend(tag::string(codes::GENRE, genre));
        }
        if let Some(n) = self.track_number {
            payload.extend(tag::u16(codes::TRACK_NUMBER, n));
        }
        if let Some(n) = self.disc_number {
            payload.extend(tag::u16(codes::DISC_NUMBER, n));
        }
        if let Some(ms) = self.duration_ms {
            payload.extend(tag::u32(codes::SONG_TIME_MS, ms));
        }
        tag::container(codes::LISTING_ITEM, &payload)
    }
}

impl NowPlaying {
    /// Decodes a metadata body, the receiver's side of [`Self::encode`].
    ///
    /// Accepts the `mlit` container or a bare run of tags, skips unknown tags, and reads strings
    /// lossily. A length running past the end is an error.
    pub fn decode(body: &[u8]) -> crate::error::Result<Self> {
        let items = split_tags(body)?;
        let inner = match items.as_slice() {
            [(code, payload)] if *code == codes::LISTING_ITEM => split_tags(payload)?,
            _ => items,
        };
        let mut out = Self::default();
        for (code, payload) in inner {
            let text = || Some(String::from_utf8_lossy(payload).into_owned());
            let number = |width: usize| -> Option<u32> {
                (payload.len() == width).then(|| {
                    payload
                        .iter()
                        .fold(0u32, |acc, b| (acc << 8) | u32::from(*b))
                })
            };
            match code {
                codes::TITLE => out.title = text(),
                codes::ARTIST => out.artist = text(),
                codes::ALBUM => out.album = text(),
                codes::GENRE => out.genre = text(),
                codes::TRACK_NUMBER => {
                    out.track_number = number(2).and_then(|n| u16::try_from(n).ok());
                }
                codes::DISC_NUMBER => {
                    out.disc_number = number(2).and_then(|n| u16::try_from(n).ok());
                }
                codes::SONG_TIME_MS => out.duration_ms = number(4),
                _ => {}
            }
        }
        Ok(out)
    }
}

/// Splits a run of DMAP tags into `(code, payload)` pairs.
fn split_tags(mut bytes: &[u8]) -> crate::error::Result<Vec<([u8; 4], &[u8])>> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < 8 {
            return Err(crate::error::AirPlayError::Protocol(
                "DMAP tag truncated in its header".to_owned(),
            ));
        }
        let code = [bytes[0], bytes[1], bytes[2], bytes[3]];
        let length = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
        let rest = &bytes[8..];
        if length > rest.len() {
            return Err(crate::error::AirPlayError::Protocol(
                "DMAP tag runs past the end of the body".to_owned(),
            ));
        }
        out.push((code, &rest[..length]));
        bytes = &rest[length..];
    }
    Ok(out)
}

fn non_empty(value: &Option<String>) -> Option<&str> {
    value.as_deref().filter(|s| !s.is_empty())
}

/// Which image format an artwork body is, and its `Content-Type`. `#[non_exhaustive]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ArtworkFormat {
    /// `image/jpeg`. Observed (pyatv).
    Jpeg,
    /// `image/png`. Assumed.
    Png,
}

impl ArtworkFormat {
    /// The `Content-Type` to send an artwork body with.
    #[must_use]
    pub fn content_type(self) -> &'static str {
        match self {
            Self::Jpeg => "image/jpeg",
            Self::Png => "image/png",
        }
    }
}

/// The `Content-Type` for an artwork body; the image bytes are sent as the body directly.
#[must_use]
pub fn artwork_content_type(format: ArtworkFormat) -> &'static str {
    format.content_type()
}

/// The `Session` and `RTP-Info` headers sent alongside a metadata or artwork `SET_PARAMETER`:
/// the stream's RTSP session id and the RTP position at which the change takes effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MediaPosition {
    /// The RTSP `Session` value of the stream.
    pub rtsp_session: u32,
    /// RTP sequence number at which this takes effect.
    pub rtp_sequence: u16,
    /// RTP timestamp at which this takes effect.
    pub rtp_timestamp: u32,
}

impl MediaPosition {
    /// The headers `("Session", "<n>")` and `("RTP-Info", "seq=<n>;rtptime=<n>")`. Observed
    /// (pyatv).
    #[must_use]
    pub fn headers(&self) -> [(&'static str, String); 2] {
        [
            ("Session", self.rtsp_session.to_string()),
            (
                "RTP-Info",
                format!("seq={};rtptime={}", self.rtp_sequence, self.rtp_timestamp),
            ),
        ]
    }
}

/// The `text/parameters` progress body ([`PROGRESS_CONTENT_TYPE`]): start, current and end as RTP
/// timestamps on the audio clock, not seconds. Observed (pyatv `RtspSession.play`).
#[must_use]
pub fn progress_body(start_rtptime: u32, current_rtptime: u32, end_rtptime: u32) -> Vec<u8> {
    format!("progress: {start_rtptime}/{current_rtptime}/{end_rtptime}").into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- tag primitives --------------------------------------------------------------------

    #[test]
    fn raw_tag_is_code_plus_be_length_plus_payload() {
        let bytes = tag::raw(*b"abcd", &[1, 2, 3]);
        assert_eq!(bytes, b"abcd\x00\x00\x00\x03\x01\x02\x03");
    }

    #[test]
    fn raw_tag_with_empty_payload_still_writes_the_header() {
        let bytes = tag::raw(*b"abcd", &[]);
        assert_eq!(bytes, b"abcd\x00\x00\x00\x00");
    }

    #[test]
    fn string_tag_uses_byte_length_not_char_count() {
        // "café" is 4 chars, 5 UTF-8 bytes.
        let bytes = tag::string(*b"minm", "café");
        assert_eq!(&bytes[..4], b"minm");
        assert_eq!(u32::from_be_bytes(bytes[4..8].try_into().unwrap()), 5);
        assert_eq!(&bytes[8..], "café".as_bytes());
    }

    #[test]
    fn container_tag_matches_raw() {
        assert_eq!(tag::container(*b"mlit", b"xyz"), tag::raw(*b"mlit", b"xyz"));
    }

    #[test]
    fn u8_tag_matches_pyatv_uint8_tag_shape() {
        // pyatv's uint8_tag: name + b"\x00\x00\x00\x01" + one byte.
        assert_eq!(tag::u8(*b"aeSV", 7), b"aeSV\x00\x00\x00\x01\x07");
    }

    #[test]
    fn u16_tag_is_big_endian() {
        assert_eq!(tag::u16(*b"astn", 0x0102), b"astn\x00\x00\x00\x02\x01\x02");
    }

    #[test]
    fn u32_tag_is_big_endian() {
        assert_eq!(
            tag::u32(*b"astm", 0x0102_0304),
            b"astm\x00\x00\x00\x04\x01\x02\x03\x04"
        );
    }

    #[test]
    fn u64_tag_is_big_endian() {
        assert_eq!(
            tag::u64(*b"aeSV", 0x0102_0304_0506_0708),
            b"aeSV\x00\x00\x00\x08\x01\x02\x03\x04\x05\x06\x07\x08"
        );
    }

    // -- never-panic / round-trips-through-its-own-length-accounting -----------------------

    #[test]
    fn raw_tag_never_panics_on_a_huge_payload_and_stays_internally_consistent() {
        // Nothing sane sends a >4 GiB tag value; the point is that this cannot panic or emit a
        // length prefix that disagrees with what was actually written.
        let huge = vec![0xAB_u8; 5_000_000];
        let bytes = tag::raw(*b"data", &huge);
        let declared_len = u32::from_be_bytes(bytes[4..8].try_into().unwrap()) as usize;
        assert_eq!(declared_len, bytes.len() - 8);
        assert_eq!(declared_len, huge.len());
    }

    #[test]
    fn string_tag_never_panics_and_never_splits_a_multibyte_character() {
        // A string whose length is right at a truncation boundary, and one that never gets
        // truncated at all — both must round-trip as valid UTF-8.
        for value in ["", "x", "€", "a€b€c€", &"z".repeat(70_000)] {
            let bytes = tag::string(*b"minm", value);
            let declared_len = u32::from_be_bytes(bytes[4..8].try_into().unwrap()) as usize;
            assert_eq!(declared_len, bytes.len() - 8);
            let payload = &bytes[8..];
            assert!(
                std::str::from_utf8(payload).is_ok(),
                "payload must stay valid UTF-8"
            );
        }
    }

    #[test]
    fn now_playing_encode_never_panics_on_empty_or_pathological_input() {
        let cases = [
            NowPlaying::default(),
            NowPlaying {
                title: Some(String::new()),
                artist: Some(String::new()),
                album: Some(String::new()),
                ..Default::default()
            },
            NowPlaying {
                title: Some("x".repeat(200_000)),
                duration_ms: Some(u32::MAX),
                track_number: Some(u16::MAX),
                disc_number: Some(u16::MAX),
                ..Default::default()
            },
            NowPlaying {
                title: Some("🎵 emoji title 🎶".to_owned()),
                artist: Some("naïve ☕ artist".to_owned()),
                ..Default::default()
            },
        ];
        for case in cases {
            let encoded = case.encode();
            // Always a well-formed mlit container: code, then a length matching what follows.
            assert_eq!(&encoded[..4], b"mlit");
            let declared_len = u32::from_be_bytes(encoded[4..8].try_into().unwrap()) as usize;
            assert_eq!(declared_len, encoded.len() - 8);
        }
    }

    // -- NowPlaying::encode field behaviour -------------------------------------------------

    #[test]
    fn empty_string_fields_are_omitted_not_sent_as_empty_tags() {
        let now_playing = NowPlaying {
            title: Some(String::new()),
            artist: Some("Real Artist".to_owned()),
            ..Default::default()
        };
        let encoded = now_playing.encode();
        // Only the artist tag should appear inside the container.
        assert_eq!(
            encoded,
            tag::container(
                codes::LISTING_ITEM,
                &tag::string(codes::ARTIST, "Real Artist")
            )
        );
    }

    #[test]
    fn none_fields_are_omitted() {
        let now_playing = NowPlaying::default();
        assert_eq!(
            now_playing.encode(),
            tag::container(codes::LISTING_ITEM, &[])
        );
    }

    #[test]
    fn full_now_playing_matches_field_order_title_album_artist_then_additions() {
        let now_playing = NowPlaying {
            title: Some("Title".to_owned()),
            album: Some("Album".to_owned()),
            artist: Some("Artist".to_owned()),
            genre: Some("Genre".to_owned()),
            track_number: Some(3),
            disc_number: Some(1),
            duration_ms: Some(123_456),
        };
        let mut expected = Vec::new();
        expected.extend(tag::string(codes::TITLE, "Title"));
        expected.extend(tag::string(codes::ALBUM, "Album"));
        expected.extend(tag::string(codes::ARTIST, "Artist"));
        expected.extend(tag::string(codes::GENRE, "Genre"));
        expected.extend(tag::u16(codes::TRACK_NUMBER, 3));
        expected.extend(tag::u16(codes::DISC_NUMBER, 1));
        expected.extend(tag::u32(codes::SONG_TIME_MS, 123_456));
        assert_eq!(
            now_playing.encode(),
            tag::container(codes::LISTING_ITEM, &expected)
        );
    }

    // -- artwork / progress / headers --------------------------------------------------------

    #[test]
    fn artwork_content_type_picks_jpeg_or_png() {
        assert_eq!(artwork_content_type(ArtworkFormat::Jpeg), "image/jpeg");
        assert_eq!(artwork_content_type(ArtworkFormat::Png), "image/png");
    }

    #[test]
    fn media_position_headers_match_pyatv_shape() {
        let position = MediaPosition {
            rtsp_session: 42,
            rtp_sequence: 7,
            rtp_timestamp: 90000,
        };
        assert_eq!(
            position.headers(),
            [
                ("Session", "42".to_owned()),
                ("RTP-Info", "seq=7;rtptime=90000".to_owned()),
            ]
        );
    }

    #[test]
    fn progress_body_matches_pyatv_shape() {
        assert_eq!(progress_body(0, 44100, 88200), b"progress: 0/44100/88200");
    }

    #[test]
    fn progress_body_never_panics_at_the_numeric_extremes() {
        let body = progress_body(0, u32::MAX, u32::MAX);
        assert!(std::str::from_utf8(&body).is_ok());
    }

    // -- decode (receiver side) ------------------------------------------------------------

    #[test]
    fn decode_reads_back_everything_encode_writes() {
        let original = NowPlaying {
            title: Some("Title".into()),
            artist: Some("Artist".into()),
            album: Some("Album".into()),
            genre: Some("Genre".into()),
            track_number: Some(3),
            disc_number: Some(1),
            duration_ms: Some(215_000),
        };
        assert_eq!(NowPlaying::decode(&original.encode()).unwrap(), original);
    }

    #[test]
    fn decode_skips_unknown_tags_and_refuses_overruns() {
        let mut body = tag::string(*b"zzzz", "ignored");
        body.extend(tag::string(codes::TITLE, "t"));
        assert_eq!(
            NowPlaying::decode(&body).unwrap().title.as_deref(),
            Some("t")
        );
        assert!(NowPlaying::decode(b"minm   	abc").is_err());
        assert!(NowPlaying::decode(b"min").is_err());
        assert_eq!(NowPlaying::decode(b"").unwrap(), NowPlaying::default());
    }
}
