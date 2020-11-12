//! Noise Protocol Framework API
//!
//! This module is a wrapper for noise functionality provided by snow to build
//! and use secure communication channels between revault infrastructure machines.
//!

use crate::error::Error;
use snow::{resolvers::SodiumResolver, Builder, HandshakeState, TransportState};

/// The size of a key, either public or private, on the Curve25519
pub const KEY_SIZE: usize = 32;
/// Size of the poly1305 MAC
pub const MAC_SIZE: usize = 16;
/// Max message size pecified by Noise Protocol Framework
pub const NOISE_MESSAGE_MAX_SIZE: usize = 65535;
/// A 64bit integer is used for message length prefix
pub const LENGTH_PREFIX_SIZE: usize = 8;
/// Message header length plus its MAC
pub const NOISE_MESSAGE_HEADER_SIZE: usize = MAC_SIZE + LENGTH_PREFIX_SIZE;
/// Size of padded messages; limited by Noise Protocol Framework
pub const NOISE_PADDED_MESSAGE_SIZE: usize =
    NOISE_MESSAGE_MAX_SIZE - MAC_SIZE - NOISE_MESSAGE_HEADER_SIZE;

/// A static Noise public key
#[derive(Debug)]
pub struct NoisePubKey(pub [u8; KEY_SIZE]);

/// A static Noise private key
#[derive(Debug)]
pub struct NoisePrivKey(pub [u8; KEY_SIZE]);

/// First round of the KX handshake
#[derive(Debug)]
pub struct KXHandshakeActOne {
    state: HandshakeState,
}

pub struct KXMessageActOne(pub Vec<u8>);

impl KXHandshakeActOne {
    /// Start the first act of the handshake as an initiator (sharing e)
    pub fn initiator(
        my_privkey: &NoisePrivKey,
    ) -> Result<(KXHandshakeActOne, KXMessageActOne), Error> {
        // Build the initial initiator state
        let builder = Builder::with_resolver(
            "Noise_KX_25519_ChaChaPoly_SHA256"
                .parse()
                .expect("Valid params"),
            // FIXME: should probably be part of a context
            Box::new(SodiumResolver::default()),
        );
        let mut state = builder
            .local_private_key(&my_privkey.0)
            .build_initiator()
            .map_err(|e| Error::Noise(format!("Failed to build state for initiator: {:?}", e)))?;

        // Write the first message
        let mut msg = vec![0u8; NOISE_MESSAGE_MAX_SIZE];
        let len = state
            // FIXME: should we write something like b"revault_0" ?
            .write_message(&[], &mut msg)
            .map_err(|e| {
                Error::Noise(format!(
                    "Failed to write first message for initiator: {:?}",
                    e
                ))
            })?;
        msg.truncate(len);

        Ok((KXHandshakeActOne { state }, KXMessageActOne(msg)))
    }

    /// Start the first act of the handshake as a responder (reading e and doing wizardry with it)
    pub fn responder(
        their_pubkey: &NoisePubKey,
        message: &KXMessageActOne,
    ) -> Result<KXHandshakeActOne, Error> {
        // Build the initial responder state
        let builder = Builder::with_resolver(
            "Noise_KX_25519_ChaChaPoly_SHA256"
                .parse()
                .expect("Valid params"),
            // FIXME: should probably be part of a context
            Box::new(SodiumResolver::default()),
        );
        let mut state = builder
            .remote_public_key(&their_pubkey.0)
            .build_responder()
            .map_err(|e| Error::Noise(format!("Failed to build state for responder: {:?}", e)))?;

        // In handshake mode we don't actually care about the message
        let mut _m = vec![0u8; NOISE_MESSAGE_MAX_SIZE];
        state.read_message(&message.0, &mut _m).map_err(|e| {
            Error::Noise(format!(
                "Failed to read first message for responder: {:?}",
                e
            ))
        })?;

        Ok(KXHandshakeActOne { state })
    }
}

/// Final round of the KX handshake
#[derive(Debug)]
pub struct KXHandshakeActTwo {
    pub state: HandshakeState,
}

pub struct KXMessageActTwo(pub Vec<u8>);

impl KXHandshakeActTwo {
    /// Start the second act of the handshake as an initiator (read e, ee, se, s, es)
    pub fn initiator(
        mut handshake: KXHandshakeActOne,
        message: &KXMessageActTwo,
    ) -> Result<KXHandshakeActTwo, Error> {
        let mut _m = vec![0u8; NOISE_MESSAGE_MAX_SIZE];
        handshake
            .state
            .read_message(&message.0, &mut _m)
            .map_err(|e| {
                Error::Noise(format!("Initiator failed to read second message: {:?}", e))
            })?;

        Ok(KXHandshakeActTwo {
            state: handshake.state,
        })
    }

    /// Start the second act of the handshake as a responder (write e, ee, se, s, es)
    pub fn responder(
        mut handshake: KXHandshakeActOne,
    ) -> Result<(KXHandshakeActTwo, KXMessageActTwo), Error> {
        let mut msg = vec![0u8; NOISE_MESSAGE_MAX_SIZE];
        let len = handshake.state.write_message(&[], &mut msg).map_err(|e| {
            Error::Noise(format!("Responder failed to write second message: {:?}", e))
        })?;
        msg.truncate(len);

        Ok((
            KXHandshakeActTwo {
                state: handshake.state,
            },
            KXMessageActTwo(msg),
        ))
    }
}

/// A wrapper over Snow's transport state for a KX Noise communication channel.
#[derive(Debug)]
pub struct KXChannel {
    transport_state: TransportState,
}

impl KXChannel {
    pub fn from_handshake(state: KXHandshakeActTwo) -> Result<KXChannel, Error> {
        let transport_state = state
            .state
            .into_transport_mode()
            .map_err(|e| Error::Noise(format!("Failed to enter transport mode: {:?}", e)))?;

        Ok(KXChannel { transport_state })
    }
}

/// First round of the handshake
#[derive(Debug)]
pub struct KKHandshakeActOne {
    pub state: HandshakeState,
}

pub struct KKMessageActOne(pub Vec<u8>);

impl KKHandshakeActOne {
    /// Start the first act of the handshake as an initiator (sharing e, es, ss)
    pub fn initiator(
        my_privkey: &NoisePrivKey,
        their_pubkey: &NoisePubKey,
    ) -> Result<(KKHandshakeActOne, KKMessageActOne), Error> {
        // Build the initial initiator state
        let builder = Builder::with_resolver(
            "Noise_KK_25519_ChaChaPoly_SHA256"
                .parse()
                .expect("Valid params"),
            // FIXME: should probably be part of a context
            Box::new(SodiumResolver::default()),
        );
        let mut state = builder
            .local_private_key(&my_privkey.0)
            .remote_public_key(&their_pubkey.0)
            .build_initiator()
            .map_err(|e| Error::Noise(format!("Failed to build state for initiator: {:?}", e)))?;

        // Write the first message
        let mut msg = vec![0u8; NOISE_MESSAGE_MAX_SIZE];
        let len = state
            // FIXME: should we write something like b"revault_0" ?
            .write_message(&[], &mut msg)
            .map_err(|e| {
                Error::Noise(format!(
                    "Failed to write first message for initiator: {:?}",
                    e
                ))
            })?;
        msg.truncate(len);

        Ok((KKHandshakeActOne { state }, KKMessageActOne(msg)))
    }

    /// Start the first act of the handshake as a responder (reading e, es, ss and doing wizardry with it)
    pub fn responder(
        my_privkey: &NoisePrivKey,
        their_pubkey: &NoisePubKey,
        message: &KKMessageActOne,
    ) -> Result<KKHandshakeActOne, Error> {
        // Build the initial responder state
        let builder = Builder::with_resolver(
            "Noise_KK_25519_ChaChaPoly_SHA256"
                .parse()
                .expect("Valid params"),
            // FIXME: should probably be part of a context
            Box::new(SodiumResolver::default()),
        );
        let mut state = builder
            .local_private_key(&my_privkey.0)
            .remote_public_key(&their_pubkey.0)
            .build_responder()
            .map_err(|e| Error::Noise(format!("Failed to build state for responder: {:?}", e)))?;

        // In handshake mode we don't actually care about the message
        let mut _m = vec![0u8; NOISE_MESSAGE_MAX_SIZE];
        state.read_message(&message.0, &mut _m).map_err(|e| {
            Error::Noise(format!(
                "Failed to read first message for responder: {:?}",
                e
            ))
        })?;

        Ok(KKHandshakeActOne { state })
    }
}

/// Final round of the KK handshake
#[derive(Debug)]
pub struct KKHandshakeActTwo {
    /// Inner snow Noise KK handshake state
    pub state: HandshakeState,
}

/// Content of the message from the final round of the handshake
pub struct KKMessageActTwo(pub Vec<u8>);

impl KKHandshakeActTwo {
    /// Start the second act of the handshake as a responder (read e, ee, se)
    pub fn initiator(
        mut handshake: KKHandshakeActOne,
        message: &KKMessageActTwo,
    ) -> Result<KKHandshakeActTwo, Error> {
        // In handshake mode we don't actually care about the message
        let mut _m = vec![0u8; NOISE_MESSAGE_MAX_SIZE];
        handshake
            .state
            .read_message(&message.0, &mut _m)
            .map_err(|e| {
                Error::Noise(format!("Initiator failed to read second message: {:?}", e))
            })?;

        Ok(KKHandshakeActTwo {
            state: handshake.state,
        })
    }

    /// Start the second act of the handshake as a responder (write e, ee, se)
    pub fn responder(
        mut handshake: KKHandshakeActOne,
    ) -> Result<(KKHandshakeActTwo, KKMessageActTwo), Error> {
        let mut msg = vec![0u8; NOISE_MESSAGE_MAX_SIZE];
        let len = handshake.state.write_message(&[], &mut msg).map_err(|e| {
            Error::Noise(format!("Responder failed to write second message: {:?}", e))
        })?;
        msg.truncate(len);

        Ok((
            KKHandshakeActTwo {
                state: handshake.state,
            },
            KKMessageActTwo(msg),
        ))
    }
}

/// A wrapper over Snow's transport state for a KK Noise communication channel.
#[derive(Debug)]
pub struct KKChannel {
    transport_state: TransportState,
}

impl KKChannel {
    /// Constructs the KK Noise channel from a final stage KK handshake
    pub fn from_handshake(state: KKHandshakeActTwo) -> Result<KKChannel, Error> {
        let transport_state = state
            .state
            .into_transport_mode()
            .map_err(|e| Error::Noise(format!("Failed to enter transport mode: {:?}", e)))?;

        Ok(KKChannel { transport_state })
    }
}

/// A wrapper over Snow's transport state for a Noise communication channel.
/// Can be either KX or KK for Revault.
pub trait NoiseChannel {
    /// Get the inner transport state
    fn transport_state(&mut self) -> &mut TransportState;
}

impl NoiseChannel for KXChannel {
    fn transport_state(&mut self) -> &mut TransportState {
        &mut self.transport_state
    }
}

impl NoiseChannel for KKChannel {
    fn transport_state(&mut self) -> &mut TransportState {
        &mut self.transport_state
    }
}

/// A cyphertext encrypted with [encrypt_message]
#[derive(Debug)]
pub struct NoiseEncryptedMessage(pub Vec<u8>);

/// Use the channel to encrypt any given message. Pre-fixes the message with
/// (big-endian) length field and pads the message with 0s before encryption.
/// On success, returns the ciphertext.
pub fn encrypt_message(
    channel: &mut impl NoiseChannel,
    message: &[u8],
) -> Result<NoiseEncryptedMessage, Error> {
    let mut output = vec![0u8; NOISE_MESSAGE_MAX_SIZE];

    // Pad message
    // FIXME: padding is huge
    let mut message_body = [0u8; NOISE_PADDED_MESSAGE_SIZE];
    message_body[..message.len()].copy_from_slice(message);

    // Prefix
    let message_len: usize = MAC_SIZE + message.len();
    if message_len > NOISE_MESSAGE_MAX_SIZE {
        return Err(Error::Noise(format!("Message is too large to encrypt")));
    }
    let length_prefix: [u8; LENGTH_PREFIX_SIZE] = message_len.to_be_bytes();
    channel
        .transport_state()
        .write_message(&length_prefix, &mut output[..NOISE_MESSAGE_HEADER_SIZE])
        .map_err(|e| Error::Noise(format!("Header encryption failed: {:?}", e)))?;

    // Encrypt message
    let ciphertext_len = channel
        .transport_state()
        .write_message(&message_body[..], &mut output[NOISE_MESSAGE_HEADER_SIZE..])
        .map_err(|e| Error::Noise(format!("Message encryption failed: {:?}", e)))?;
    output.truncate(ciphertext_len + NOISE_MESSAGE_HEADER_SIZE);

    Ok(NoiseEncryptedMessage(output))
}

/// Get plaintext bytes from a Noise-encrypted message
pub fn decrypt_message(
    channel: &mut impl NoiseChannel,
    message: &NoiseEncryptedMessage,
) -> Result<Vec<u8>, Error> {
    let mut output = vec![0u8; NOISE_MESSAGE_MAX_SIZE];

    // Decrypt the header to get the message size
    let mut header = [0u8; 8];
    channel
        .transport_state()
        .read_message(&message.0[..NOISE_MESSAGE_HEADER_SIZE], &mut header)
        .map_err(|e| Error::Noise(format!("Failed to decrypt message header: {:?}", e)))?;
    let message_len = usize::from_be_bytes(header) - MAC_SIZE;

    channel
        .transport_state()
        .read_message(&message.0[NOISE_MESSAGE_HEADER_SIZE..], &mut output)
        .map_err(|e| Error::Noise(format!("Failed to decrypt message: {:?}", e)))?;
    output.truncate(message_len);

    Ok(output)
}
