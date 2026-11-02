//! Error types for cidermill-airplay.

use crate::PairingError;

/// Everything the AirPlay protocol core can fail with.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AirPlayError {
    /// A protocol message could not be parsed or was semantically invalid.
    #[error("protocol error: {0}")]
    Protocol(String),

    /// Network I/O failed mid-session.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// Resolving or connecting to `addr` failed.
    #[error("could not connect to {addr}: {source}")]
    Connect {
        /// The `host:port` that was dialled.
        addr: String,
        /// Why it failed.
        #[source]
        source: std::io::Error,
    },

    /// An encrypted frame failed authentication. The connection cannot continue.
    #[error("a frame did not authenticate")]
    Decrypt,

    /// An earlier failure retired this connection; open a new one.
    #[error("the connection failed earlier ({reason}) and cannot be used; reconnect")]
    ConnectionRetired {
        /// What retired it.
        reason: String,
    },

    /// A pairing exchange ended in a step this operation cannot use.
    #[error("unexpected pairing step: {0}")]
    UnexpectedPairingStep(String),

    /// The operation was attempted in an invalid state (e.g. write before handshake).
    #[error("invalid state: {0}")]
    InvalidState(String),

    /// A credential string could not be parsed — wrong format, bad hex, or wrong field length.
    #[error("credentials error: {0}")]
    Credentials(String),

    /// A stored pairing failed `/pair-verify`: the receiver does not hold the credential's
    /// long-term key. A genuine refusal (set up the pairing again), unlike a garbled reply
    /// ([`Self::Protocol`]) or an error TLV ([`Self::Pairing`]).
    #[error("pair-verify refused: {0}")]
    PairVerifyRefused(String),

    /// The receiver returned a pairing error.
    #[error("pairing error: {}", .0.user_message())]
    Pairing(PairingError),

    /// The receiver returned a non-2xx status on an endpoint.
    #[error("{path} returned {code}{}", reason.as_ref().map(|r| format!(": {r}")).unwrap_or_default())]
    Status {
        /// The endpoint path.
        path: String,
        /// The HTTP/RTSP status code.
        code: u16,
        /// An optional reason extracted from the response body.
        reason: Option<String>,
    },
}

impl AirPlayError {
    /// `source` with `context` in front of its message, its [`std::io::ErrorKind`] kept.
    pub(crate) fn io_context(context: &str, source: std::io::Error) -> Self {
        Self::Io(std::io::Error::new(
            source.kind(),
            format!("{context}: {source}"),
        ))
    }
}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, AirPlayError>;
