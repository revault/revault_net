use std::{error, fmt};

/// An error specific to the management of Revault transactions and scripts.
#[derive(PartialEq, Eq, Debug)]
pub enum Error {
    /// Error while using snow API
    Noise(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Noise(ref e) => write!(f, "Noise Error: {}", e),
        }
    }
}

impl error::Error for Error {}
