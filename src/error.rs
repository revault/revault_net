use serde::{Deserialize, Serialize};
use std::{error, fmt};

/// An error enum for revault_net functionality
#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Error {
    /// Error when using messages API
    Message(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Message(ref e) => write!(f, "Message Error: {}", e),
        }
    }
}

impl error::Error for Error {}
