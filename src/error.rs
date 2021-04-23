//! Revault_net error module

use std::{error, fmt};

#[derive(Debug)]
pub enum NoiseError {
    /// Error from Snow's internals
    Snow(snow::error::Error),
    /// An invalid plaintext was passed for encryption
    InvalidPlaintext,
    /// An invalid ciphertext was passed for decryption
    InvalidCiphertext,
    /// Handshake message was invalid
    BadHandshake,
    /// Remote static public key mismatch from passed keys
    MissingStaticKey,
}

impl From<snow::error::Error> for NoiseError {
    fn from(error: snow::error::Error) -> Self {
        Self::Snow(error)
    }
}

impl fmt::Display for NoiseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Snow(ref e) => write!(f, "Snow Error: {}", e),
            Self::InvalidPlaintext => write!(f, "Invalid plaintext. Message too large?"),
            Self::InvalidCiphertext => write!(f, "Invalid ciphertext. Message too large?"),
            Self::BadHandshake => write!(f, "Invalid handshake magic bytes"),
            Self::MissingStaticKey => write!(
                f,
                "Missing sender's static public key to respond to handshake"
            ),
        }
    }
}

impl error::Error for NoiseError {}

/// An error enum for revault_net functionality
#[derive(Debug)]
pub enum Error {
    /// Noise protocol related error
    Noise(NoiseError),
    /// Transport error
    Transport(std::io::Error),
    /// JSON serialization / deserialization error.
    Json(serde_json::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Noise(ref e) => write!(f, "Noise Error: {}", e),
            Error::Transport(ref e) => write!(f, "Transport Error: {}", e),
            Error::Json(ref e) => write!(f, "Json error: '{}'", e),
        }
    }
}

impl error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::Transport(error)
    }
}

impl From<NoiseError> for Error {
    fn from(error: NoiseError) -> Self {
        Self::Noise(error)
    }
}

impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}
