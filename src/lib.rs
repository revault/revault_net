//! Revault Networking lib
//!
//! Generalistic routines to work with Revault-specific network messages, server-client noise handshakes, and tor.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

pub mod message;

pub mod noise;

pub mod transport;

mod error;
pub use error::Error;

#[cfg(feature = "tor")]
pub mod tor;

pub use revault_tx::bitcoin;
pub use sodiumoxide;
