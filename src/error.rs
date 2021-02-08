//! Revault_net error module

use std::{error, fmt};

/// An error enum for revault_net functionality
#[derive(Debug)]
pub enum Error {
    /// Error while using noise API
    Noise(snow::error::Error),
    /// Transport error
    Transport(std::io::Error),
    /// FIXME: remove this generic error variant
    Other(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Noise(ref e) => write!(f, "Noise Error: {}", e),
            Error::Transport(ref e) => write!(f, "Transport Error: {}", e),
            Error::Other(ref e) => write!(f, "Other Error: {}", e),
        }
    }
}

impl error::Error for Error {}

impl From<snow::error::Error> for Error {
    fn from(error: snow::error::Error) -> Self {
        Error::Noise(error)
    }
}

impl From<snow::error::PatternProblem> for Error {
    fn from(error: snow::error::PatternProblem) -> Self {
        Error::Noise(snow::error::Error::Pattern(error))
    }
}

impl From<snow::error::Prerequisite> for Error {
    fn from(error: snow::error::Prerequisite) -> Self {
        Error::Noise(snow::error::Error::Prereq(error))
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Error::Transport(error)
    }
}
