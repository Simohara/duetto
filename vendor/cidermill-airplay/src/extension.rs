//! Receiver extension points: a host-supplied handler for requests this crate does not answer
//! itself, and for session keys it cannot derive itself. Sans-io.
//!
//! A sender may authenticate by a scheme this crate does not implement (the `Authentication_*`
//! feature bits, [`crate::Features`]) and may send its session key wrapped (`ekey`/`eiv`).
//!
//! * [`ReceiverExtension`] ([`crate::receiver::ReceiverConfig::extension`]) says which requests it
//!   answers ([`ReceiverExtension::claims`]) and starts one [`ExtensionSession`] per connection.
//! * [`ExtensionSession`] answers each claimed request and unwraps the session key.
//!
//! The connection enforces [`EXCHANGE_MAX_STEPS`] and [`EXCHANGE_DEADLINE`], allows one exchange,
//! and never offers pairing, `/info`, `OPTIONS`, session or stream requests. Relayed bytes pass
//! through untouched. With no extension, authentication paths get a bodiless 404 and a wrapped key
//! is refused with 501. On the sender side, use [`crate::client::ControlChannel::post_bytes`].

use std::time::Duration;

use crate::error::{AirPlayError, Result};
use crate::rtsp::Request;

/// Most claimed requests one connection relays before giving up on an exchange that never finishes.
pub const EXCHANGE_MAX_STEPS: u32 = 16;

/// Deadline for a whole exchange, counted from the first claimed request on a connection.
pub const EXCHANGE_DEADLINE: Duration = Duration::from_secs(15);

/// A receiver extension: answers the requests it claims, one [`ExtensionSession`] per connection.
///
/// Held by [`crate::receiver::ReceiverConfig::extension`]; `None` is the default.
pub trait ReceiverExtension: Send + Sync + std::fmt::Debug {
    /// Whether this extension answers `method path` (the target without its query).
    ///
    /// Asked before the encryption gate, so a claimed path is answered on an unpaired connection
    /// too. A claimed path is the extension's alone: claim only paths the crate does not handle.
    fn claims(&self, method: &str, path: &str) -> bool;

    /// A fresh session, started on the connection's first claimed request.
    ///
    /// # Errors
    ///
    /// The request is answered `400`.
    fn start(&self) -> Result<Box<dyn ExtensionSession>>;
}

/// One connection's extension state.
pub trait ExtensionSession: Send {
    /// Answers one claimed request.
    ///
    /// `Some(body)` is sent back as a `200` with `Content-Type: application/octet-stream`. `None`
    /// means the exchange is finished: the request is answered with an empty `200`, the session is
    /// **kept** for [`Self::unwrap_session_key`], and any later claimed request on the connection
    /// is answered the same way without calling this again.
    ///
    /// # Errors
    ///
    /// Anything; the request is answered `400` and the session is dropped.
    fn step(&mut self, request: &Request) -> Result<Option<Vec<u8>>>;

    /// Turns the session `SETUP`'s wrapped key (`ekey`) into the 16-byte key streams are keyed
    /// from.
    ///
    /// Called once per stream `SETUP` of a wrapped-key session on a pair-verified connection, after
    /// at least one request. The default unwraps nothing.
    ///
    /// # Errors
    ///
    /// The stream `SETUP` is answered `400` and the session is dropped.
    fn unwrap_session_key(&mut self, wrapped: &[u8]) -> Result<[u8; 16]> {
        let _ = wrapped;
        Err(AirPlayError::Protocol(
            "this receiver extension unwraps no session keys".to_owned(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtsp::Protocol;

    struct AuthOnly;
    impl ExtensionSession for AuthOnly {
        fn step(&mut self, _request: &Request) -> Result<Option<Vec<u8>>> {
            Ok(None)
        }
    }

    #[test]
    fn an_extension_that_only_authenticates_unwraps_nothing_by_default() {
        let mut session = AuthOnly;
        let request = Request::new("POST", "/x", Protocol::Rtsp, Vec::new());
        assert_eq!(session.step(&request).unwrap(), None);
        let err = session.unwrap_session_key(&[0; 72]).unwrap_err();
        assert!(err.to_string().contains("unwraps no session keys"), "{err}");
    }
}
