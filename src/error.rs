//! Revault_net error module

use std::{error, fmt};

/// An error enum for revault_net functionality
#[derive(PartialEq, Eq, Debug)]
pub enum Error {
    /// Error when using messages API
    Message(String),
    /// Error while using snow API
    Noise(String),
    /// Transport error
    Transport(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Message(ref e) => write!(f, "Message Error: {}", e),
            Error::Noise(ref e) => write!(f, "Noise Error: {}", e),
            Error::Transport(ref e) => write!(f, "Transport Error: {}", e),
        }
    }
}

impl error::Error for Error {}
