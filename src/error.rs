//! Revault_net error module

use std::{error, fmt};

use crate::noise::{MAC_SIZE, NOISE_MESSAGE_MAX_SIZE, NOISE_PLAINTEXT_MAX_SIZE};

#[derive(Debug)]
pub enum NoiseError {
    /// Error from Snow's internals
    Snow(snow::error::Error),
    /// A too large plaintext message was passed for encryption
    TooLargePlaintext(usize),
    /// A too large or too small ciphertext was passed for decryption
    InvalidCiphertextSize(usize),
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
            Self::TooLargePlaintext(size) => write!(
                f,
                "Message too large to encrypt: '{}' bytes but max is '{}'",
                size, NOISE_PLAINTEXT_MAX_SIZE
            ),
            Self::InvalidCiphertextSize(size) => {
                write!(
                    f,
                    "Invalid ciphertext size. Size is '{}' bytes but must \
                     be comprised in between '{}' and '{}' (included)",
                    size, MAC_SIZE, NOISE_MESSAGE_MAX_SIZE
                )
            }
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
