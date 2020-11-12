//! Revault_net error module

use std::{error, fmt};

/// An error enum for revault_net functionality
#[derive(PartialEq, Eq, Debug)]
pub enum Error {
    /// Error while using snow API
    Noise(String),
    /// Error while using entity map
    EntityMap(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Noise(ref e) => write!(f, "Noise Error: {}", e),
            Error::EntityMap(ref e) => write!(f, "Entity Map Error: {}", e),
        }
    }
}

impl error::Error for Error {}
