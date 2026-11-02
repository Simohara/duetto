//! Sans-io RTSP/HTTP message codec for the AirPlay control channel.
//!
//! AirPlay multiplexes HTTP/1.1 (`/info`, `/play`, pairing) and RTSP/1.0 (`ANNOUNCE`, `SETUP`,
//! `RECORD`, `SET_PARAMETER`) on one port 7000 connection. Both share a shape, so one codec serves
//! both and the protocol token is carried. No I/O: the parser is fuzzable in safe Rust.

use crate::error::{AirPlayError, Result};

/// Largest header block buffered before the peer is declared hostile.
pub const MAX_HEADER_BYTES: usize = 64 * 1024;

/// Largest body accepted on the control channel. A decoder can use a smaller cap
/// ([`Decoder::set_max_body`]), as the receiver does before pairing ([`PRE_AUTH_MAX_BODY_BYTES`]).
pub const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;

/// The body cap a receiver applies before a connection has paired. Assumed: nothing an
/// unauthenticated sender may send is larger (an iPhone's largest pre-pairing body was 60 bytes).
pub const PRE_AUTH_MAX_BODY_BYTES: usize = 64 * 1024;

/// A case-insensitive header collection that preserves insertion order (some receivers care).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Headers {
    entries: Vec<(String, String)>,
}

impl Headers {
    /// Creates an empty header set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends a header, keeping any existing header of the same name.
    pub fn append(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.entries.push((name.into(), value.into()));
    }

    /// Sets a header, replacing the first existing one of that name and dropping any duplicates.
    pub fn set(&mut self, name: impl Into<String>, value: impl Into<String>) {
        let name = name.into();
        let value = value.into();
        if let Some(slot) = self
            .entries
            .iter_mut()
            .find(|(existing, _)| existing.eq_ignore_ascii_case(&name))
        {
            slot.1 = value;
            let lowered = name.to_ascii_lowercase();
            let mut seen = false;
            self.entries.retain(|(existing, _)| {
                if existing.to_ascii_lowercase() == lowered {
                    let keep = !seen;
                    seen = true;
                    return keep;
                }
                true
            });
            return;
        }
        self.entries.push((name, value));
    }

    /// Reads the first header with this name, case-insensitively.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|(existing, _)| existing.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// Every header, in wire order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
    }

    /// Number of headers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether there are no headers.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The body length per RFC 9112 §6.3: `Transfer-Encoding` is refused (this codec frames by
    /// length only), and every `Content-Length` must be the same run of digits, or the message is
    /// refused, so two parsers cannot disagree about the message boundary.
    fn content_length(&self, cap: usize) -> Result<usize> {
        if self.get("Transfer-Encoding").is_some() {
            return Err(AirPlayError::Protocol(
                "Transfer-Encoding is not supported on the control channel (no chunked bodies); \
                 send a Content-Length"
                    .to_owned(),
            ));
        }
        let mut length: Option<usize> = None;
        let values = self
            .entries
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("Content-Length"))
            .flat_map(|(_, value)| value.split(','));
        for raw in values {
            let raw = raw.trim();
            if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
                return Err(AirPlayError::Protocol(
                    "Content-Length is not a number".to_owned(),
                ));
            }
            let value: usize = raw
                .parse()
                .map_err(|_| AirPlayError::Protocol("Content-Length exceeds the cap".to_owned()))?;
            if length.is_some_and(|seen| seen != value) {
                return Err(AirPlayError::Protocol(
                    "conflicting Content-Length values".to_owned(),
                ));
            }
            length = Some(value);
        }
        let value = length.unwrap_or(0);
        if value > cap {
            return Err(AirPlayError::Protocol(
                "Content-Length exceeds the cap".to_owned(),
            ));
        }
        Ok(value)
    }
}

/// Which dialect a message is written in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Protocol {
    /// `RTSP/1.0` — the audio and mirroring control flow.
    Rtsp,
    /// `HTTP/1.1` — `/info`, `/play`, `/photo`, `/pair-setup`, `/pair-verify`.
    Http,
}

impl Protocol {
    /// The token as it appears on the wire.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Protocol::Rtsp => "RTSP/1.0",
            Protocol::Http => "HTTP/1.1",
        }
    }

    fn parse(token: &str) -> Result<Self> {
        match token {
            "RTSP/1.0" => Ok(Protocol::Rtsp),
            "HTTP/1.1" | "HTTP/1.0" => Ok(Protocol::Http),
            other => Err(AirPlayError::Protocol(format!(
                "unsupported protocol token, {} characters",
                other.len()
            ))),
        }
    }
}

/// One request, in either dialect.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Request {
    /// `GET`, `POST`, `SETUP`, `RECORD`, `SET_PARAMETER`…
    pub method: String,
    /// Request target, e.g. `/info` or `rtsp://203.0.113.51/12345`.
    pub uri: String,
    /// Dialect to write on the request line.
    pub protocol: Protocol,
    /// Headers, in wire order.
    pub headers: Headers,
    /// Body bytes; empty when there is none. [`Self::encode`] writes `Content-Length` from it.
    pub body: Vec<u8>,
}

impl Request {
    /// Builds a request, with a `Content-Length` header (its value is written from the body at
    /// [`Self::encode`]).
    #[must_use]
    pub fn new(
        method: impl Into<String>,
        uri: impl Into<String>,
        protocol: Protocol,
        body: Vec<u8>,
    ) -> Self {
        let mut headers = Headers::new();
        headers.set("Content-Length", body.len().to_string());
        Self {
            method: method.into(),
            uri: uri.into(),
            protocol,
            headers,
            body,
        }
    }

    /// Serializes the request onto the wire. `Content-Length` is written from [`Self::body`] as it
    /// is now (in the place of the first such header, or last when there is none and the body is
    /// not empty), whatever the header holds.
    ///
    /// Never writes a line break into the head: a CR, LF or NUL in the method, URI or a header is
    /// written as a space. [`Self::try_encode`] refuses them instead; use it for anything a caller
    /// or a peer supplied.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128 + self.body.len());
        push_field(&mut out, &self.method);
        out.push(b' ');
        push_field(&mut out, &self.uri);
        out.push(b' ');
        out.extend_from_slice(self.protocol.token().as_bytes());
        out.extend_from_slice(b"\r\n");
        write_headers(&mut out, &self.headers, self.body.len());
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&self.body);
        out
    }

    /// [`Self::encode`], after [`Self::validate`].
    ///
    /// # Errors
    ///
    /// What [`Self::validate`] refuses.
    pub fn try_encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        Ok(self.encode())
    }

    /// Checks that the request can be written as it reads: the method and every header name are
    /// RFC 9110 tokens, the URI has no space or control character, and no header value holds a
    /// CR, LF or NUL.
    ///
    /// # Errors
    ///
    /// The first field that breaks one of those, as a protocol error.
    pub fn validate(&self) -> Result<()> {
        if !is_token(&self.method) {
            return Err(field_error("the method is not a token"));
        }
        if self.uri.is_empty() || self.uri.bytes().any(|b| b <= b' ' || b == 0x7F) {
            return Err(field_error(
                "the URI is empty or holds a space or control character",
            ));
        }
        validate_headers(&self.headers)
    }
}

/// One response, in either dialect.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Response {
    /// Dialect from the status line.
    pub protocol: Protocol,
    /// Numeric status, e.g. 200.
    pub status: u16,
    /// Reason phrase, e.g. `OK`. May be empty; receivers vary.
    pub reason: String,
    /// Headers, in wire order.
    pub headers: Headers,
    /// Body bytes; empty when there is none.
    pub body: Vec<u8>,
}

impl Response {
    /// Creates a response.
    #[must_use]
    pub fn new(protocol: Protocol, status: u16, reason: &str, body: Vec<u8>) -> Self {
        Self {
            protocol,
            status,
            reason: reason.to_owned(),
            headers: Headers::new(),
            body,
        }
    }

    /// Whether the status is 2xx.
    #[must_use]
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// The `CSeq` header as a number, when present (RTSP request/response correlation).
    #[must_use]
    pub fn sequence(&self) -> Option<u32> {
        self.headers.get("CSeq")?.trim().parse().ok()
    }

    /// Serializes the response onto the wire. `Content-Length` is written from [`Self::body`] as
    /// it is now (in the place of the first such header, or last when there is none and the body
    /// is not empty), so the reply can be framed.
    ///
    /// Never writes a line break into the head: a CR, LF or NUL in the reason or a header is
    /// written as a space. [`Self::try_encode`] refuses them instead.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128 + self.body.len());
        out.extend_from_slice(self.protocol.token().as_bytes());
        out.push(b' ');
        out.extend_from_slice(self.status.to_string().as_bytes());
        out.push(b' ');
        push_field(&mut out, &self.reason);
        out.extend_from_slice(b"\r\n");
        write_headers(&mut out, &self.headers, self.body.len());
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&self.body);
        out
    }

    /// [`Self::encode`], after [`Self::validate`].
    ///
    /// # Errors
    ///
    /// What [`Self::validate`] refuses.
    pub fn try_encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        Ok(self.encode())
    }

    /// Checks that the response can be written as it reads: no CR, LF or NUL in the reason or a
    /// header value, and every header name an RFC 9110 token.
    ///
    /// # Errors
    ///
    /// The first field that breaks one of those, as a protocol error.
    pub fn validate(&self) -> Result<()> {
        if has_line_break(&self.reason) {
            return Err(field_error("the reason holds a CR, LF or NUL"));
        }
        validate_headers(&self.headers)
    }
}

/// Writes every header, with `Content-Length` set to `body_len`: in the first such header's place,
/// later ones dropped, or appended when there is none and the body is not empty.
fn write_headers(out: &mut Vec<u8>, headers: &Headers, body_len: usize) {
    let mut length_written = false;
    for (name, value) in headers.iter() {
        if name.eq_ignore_ascii_case("Content-Length") {
            if !length_written {
                push_field(out, name);
                out.extend_from_slice(format!(": {body_len}\r\n").as_bytes());
                length_written = true;
            }
            continue;
        }
        push_field(out, name);
        out.extend_from_slice(b": ");
        push_field(out, value);
        out.extend_from_slice(b"\r\n");
    }
    if !length_written && body_len > 0 {
        out.extend_from_slice(format!("Content-Length: {body_len}\r\n").as_bytes());
    }
}

/// Appends a head field with every CR, LF and NUL written as a space.
fn push_field(out: &mut Vec<u8>, field: &str) {
    out.extend(field.bytes().map(|b| match b {
        b'\r' | b'\n' | 0 => b' ',
        other => other,
    }));
}

fn has_line_break(field: &str) -> bool {
    field.bytes().any(|b| matches!(b, b'\r' | b'\n' | 0))
}

/// An RFC 9110 token: one or more of the visible ASCII characters that are not delimiters.
fn is_token(field: &str) -> bool {
    !field.is_empty()
        && field
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

fn validate_headers(headers: &Headers) -> Result<()> {
    for (name, value) in headers.iter() {
        if !is_token(name) {
            return Err(field_error("a header name is not a token"));
        }
        if has_line_break(value) {
            return Err(field_error("a header value holds a CR, LF or NUL"));
        }
    }
    Ok(())
}

fn field_error(what: &str) -> AirPlayError {
    AirPlayError::Protocol(format!("refusing to write the message: {what}"))
}

/// Incremental decoder: feed it socket bytes, take whole messages out.
///
/// Generic over the message kind so sender (responses) and receiver (requests) share limits.
/// The head search is incremental, so a byte-at-a-time peer costs linear work.
#[derive(Debug)]
pub struct Decoder {
    buffer: Vec<u8>,
    /// How far [`find_header_end`] has looked without finding the end of the head.
    scanned: usize,
    /// The largest `Content-Length` accepted.
    max_body: usize,
}

impl Default for Decoder {
    fn default() -> Self {
        Self {
            buffer: Vec::new(),
            scanned: 0,
            max_body: MAX_BODY_BYTES,
        }
    }
}

impl Decoder {
    /// Creates an empty decoder with the [`MAX_BODY_BYTES`] cap.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Changes the largest body accepted from the next message on; a larger `Content-Length` is an
    /// error before any body is buffered.
    pub fn set_max_body(&mut self, max_body: usize) {
        self.max_body = max_body.min(MAX_BODY_BYTES);
    }

    /// The largest body currently accepted.
    #[must_use]
    pub fn max_body(&self) -> usize {
        self.max_body
    }

    /// Adds freshly-read bytes.
    pub fn push(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    /// Bytes buffered but not yet consumed.
    #[must_use]
    pub fn buffered(&self) -> usize {
        self.buffer.len()
    }

    /// Takes the next complete response, or `None` when more bytes are needed.
    pub fn next_response(&mut self) -> Result<Option<Response>> {
        let Some((head, body_start, body_len)) = self.split_message()? else {
            return Ok(None);
        };

        let (status_line, headers) = parse_head(&head)?;
        let mut parts = status_line.splitn(3, ' ');
        let protocol = Protocol::parse(parts.next().unwrap_or_default())?;
        let status: u16 =
            parts.next().unwrap_or_default().parse().map_err(|_| {
                AirPlayError::Protocol("status line has no numeric status".to_owned())
            })?;
        let reason = parts.next().unwrap_or_default().trim().to_owned();

        let body = self.take_message(body_start, body_len);
        Ok(Some(Response {
            protocol,
            status,
            reason,
            headers,
            body,
        }))
    }

    /// Takes the next complete request, or `None` when more bytes are needed (receiver side).
    pub fn next_request(&mut self) -> Result<Option<Request>> {
        let Some((head, body_start, body_len)) = self.split_message()? else {
            return Ok(None);
        };

        let (request_line, headers) = parse_head(&head)?;
        let mut parts = request_line.splitn(3, ' ');
        let method = parts.next().unwrap_or_default().to_owned();
        let uri = parts.next().unwrap_or_default().to_owned();
        let protocol = Protocol::parse(parts.next().unwrap_or_default().trim())?;
        if method.is_empty() || uri.is_empty() {
            return Err(AirPlayError::Protocol("malformed request line".to_owned()));
        }

        let body = self.take_message(body_start, body_len);
        Ok(Some(Request {
            method,
            uri,
            protocol,
            headers,
            body,
        }))
    }

    /// Finds a complete message. Returns the head bytes, where the body starts and how long it is.
    fn split_message(&mut self) -> Result<Option<(Vec<u8>, usize, usize)>> {
        // A terminator can straddle the previous read's end by up to three bytes.
        let from = self.scanned.saturating_sub(3);
        let Some(header_end) = find_header_end(&self.buffer, from) else {
            self.scanned = self.buffer.len();
            if self.buffer.len() > MAX_HEADER_BYTES {
                return Err(AirPlayError::Protocol(
                    "header block exceeded the cap without terminating".to_owned(),
                ));
            }
            return Ok(None);
        };
        if header_end.head_len > MAX_HEADER_BYTES {
            return Err(AirPlayError::Protocol(
                "header block exceeded the cap".to_owned(),
            ));
        }
        // Found: remember where, so waiting for the body does not rescan the head.
        self.scanned = header_end.head_len;

        let head = self.buffer[..header_end.head_len].to_vec();
        let body_start = header_end.body_start;

        // Parse just the headers to learn the body length; the caller re-parses the head.
        let (_, headers) = parse_head(&head)?;
        let body_len = headers.content_length(self.max_body)?;

        if self.buffer.len() < body_start + body_len {
            return Ok(None);
        }

        Ok(Some((head, body_start, body_len)))
    }

    /// Removes one message from the front of the buffer and returns its body. The common case —
    /// the buffer holds exactly one message — moves the buffer out rather than copying the body.
    fn take_message(&mut self, body_start: usize, body_len: usize) -> Vec<u8> {
        self.scanned = 0;
        let rest = self.buffer.split_off(body_start + body_len);
        let mut body = std::mem::replace(&mut self.buffer, rest);
        body.drain(..body_start);
        body
    }
}

struct HeaderEnd {
    head_len: usize,
    body_start: usize,
}

/// Finds the blank line ending the head from `from` on; accepts CRLF CRLF, LF LF and LF CRLF.
fn find_header_end(buffer: &[u8], from: usize) -> Option<HeaderEnd> {
    let mut i = from;
    while i + 1 < buffer.len() {
        if buffer[i] == b'\n' && buffer[i + 1] == b'\n' {
            return Some(HeaderEnd {
                head_len: i,
                body_start: i + 2,
            });
        }
        if i + 3 < buffer.len()
            && buffer[i] == b'\r'
            && buffer[i + 1] == b'\n'
            && buffer[i + 2] == b'\r'
            && buffer[i + 3] == b'\n'
        {
            return Some(HeaderEnd {
                head_len: i,
                body_start: i + 4,
            });
        }
        // Mixed: a bare-LF last header line followed by a CRLF blank line.
        if i + 2 < buffer.len()
            && buffer[i] == b'\n'
            && buffer[i + 1] == b'\r'
            && buffer[i + 2] == b'\n'
        {
            return Some(HeaderEnd {
                head_len: i,
                body_start: i + 3,
            });
        }
        i += 1;
    }
    None
}

/// Splits a head block into its first line and its headers.
fn parse_head(head: &[u8]) -> Result<(String, Headers)> {
    let text = std::str::from_utf8(head)
        .map_err(|_| AirPlayError::Protocol("head block is not valid UTF-8".to_owned()))?;
    let mut lines = text.split('\n');
    let first = lines
        .next()
        .ok_or_else(|| AirPlayError::Protocol("empty message".to_owned()))?
        .trim_end_matches('\r')
        .to_owned();
    if first.is_empty() {
        return Err(AirPlayError::Protocol("empty first line".to_owned()));
    }

    let mut headers = Headers::new();
    for line in lines {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(AirPlayError::Protocol(
                "header line has no colon".to_owned(),
            ));
        };
        // RFC 9112 §5.1/§5.2: whitespace before the colon and obsolete line folding are refused,
        // not trimmed (trimming is how parsers disagree about `Content-Length : 5`).
        if name.is_empty() || name.bytes().any(|b| b == b' ' || b == b'\t') {
            return Err(AirPlayError::Protocol(
                "header field name is empty or contains whitespace".to_owned(),
            ));
        }
        headers.append(name, value.trim());
    }

    Ok((first, headers))
}
