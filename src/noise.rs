//! Noise Protocol Framework API
//!
//! This module is a wrapper for noise functionality provided by snow to build
//! and use secure communication channels between revault infrastructure machines.
//!
//! This work was inspired by David Anthony Stainton's work on mix_link,
//! found at https://github.com/sphinx-cryptography/mix_link/blob/master/src/messages.rs
//!

use crate::error::Error;
use snow::{
    params::NoiseParams, resolvers::SodiumResolver, Builder, HandshakeState, TransportState,
};
use std::convert::TryInto;

pub const KEY_SIZE: usize = 32;
pub const MAC_SIZE: usize = 16;
pub const NOISE_MESSAGE_MAX_SIZE: usize = 65535;
pub const NOISE_MESSAGE_MIN_SIZE: usize = KEY_SIZE;
/// Message header length plus its MAC
pub const NOISE_MESSAGE_HEADER_SIZE: usize = MAC_SIZE + 8;
/// Size of padded messages; limited by Noise Protocol Framework
pub const NOISE_PADDED_MESSAGE_SIZE: usize =
    NOISE_MESSAGE_MAX_SIZE - MAC_SIZE - NOISE_MESSAGE_HEADER_SIZE;

/// State enum used to enforce correct sequence of handshake messages
#[derive(PartialEq, Debug, Clone)]
pub enum State {
    /// Channel Builder initialized
    Init,
    /// Client sent message A
    ClientSentMessageA,
    /// Server received message A
    ServerRecievedMessageA,
    /// Server sent message B
    ServerSentMessageB,
    /// Client recieved message B
    ClientRecievedMessageB,
}

/// Enum used to specify which Noise Handshake parameters to use
#[derive(PartialEq, Debug, Clone)]
pub enum HandshakeChoice {
    /// KX handshake type; only initiator's static public key known to responder.
    Kx,
    /// KK handshake type; initiator's and responder's know each others static public key.
    Kk,
}

/// Newtype for public and private keys
#[derive(Debug, PartialEq, Clone)]
pub struct NoiseKey([u8; KEY_SIZE]);

impl NoiseKey {
    /// Constructor for NoiseKey from an appropriately sized vector
    pub fn from_vec(key: Vec<u8>) -> Result<NoiseKey, Error> {
        if key.len() != KEY_SIZE {
            return Err(Error::Noise(format!("Invalid key size")));
        }
        let key_array: [u8; KEY_SIZE] = key[..].try_into().map_err(|e| {
            Error::Noise(format!(
                "Failed to convert key as vector into an array: {:?}",
                e
            ))
        })?;
        Ok(NoiseKey(key_array))
    }
}

/// A type to specify channel_inputs, including the static private key used
/// to authenticate messages and the remote public key from the configuration
/// file.
#[derive(PartialEq, Debug, Clone)]
pub struct ChannelInputs {
    // Key used to authenticate and encrypt noise messages
    authentication_key: NoiseKey,
    // Static public key of remote peer
    remote_public_key: Option<NoiseKey>,
    // Handshake choice for this session
    handshake_choice: HandshakeChoice,
    // Initiator of handshake or not
    is_initiator: bool,
}

/// Clients and Servers can use ChannelBuilder to enact a noise handshake and
/// establish a secure Channel.
#[derive(Debug)]
pub struct ChannelBuilder {
    handshake_state: HandshakeState,
    state: State,
}

impl ChannelBuilder {
    /// Constructor for ChannelBuilder
    pub fn new(channel_inputs: ChannelInputs) -> Result<ChannelBuilder, Error> {
        let noise_params: NoiseParams = match channel_inputs.handshake_choice {
            HandshakeChoice::Kk => "Noise_KK_25519_ChaChaPoly_SHA256"
                .parse()
                .map_err(|e| Error::Noise(format!("Invalid Noise Pattern: {}", e)))?,
            HandshakeChoice::Kx => "Noise_KX_25519_ChaChaPoly_SHA256"
                .parse()
                .map_err(|e| Error::Noise(format!("Invalid Noise Pattern: {}", e)))?,
        };

        let noise_builder: Builder =
            Builder::with_resolver(noise_params, Box::new(SodiumResolver::default()));

        if channel_inputs.is_initiator {
            // Don't always have pubkey for remote
            if channel_inputs.remote_public_key.is_none() {
                let handshake_state = noise_builder
                    .local_private_key(&channel_inputs.authentication_key.0)
                    .build_initiator()
                    .map_err(|e| {
                        Error::Noise(format!(
                            "Failed to build HandshakeState for initiator: {:?}",
                            e
                        ))
                    })?;

                return Ok(ChannelBuilder {
                    handshake_state: handshake_state,
                    state: State::Init,
                });
            } else {
                let handshake_state = noise_builder
                    .local_private_key(&channel_inputs.authentication_key.0)
                    .remote_public_key(&channel_inputs.remote_public_key.unwrap().0)
                    .build_initiator()
                    .map_err(|e| {
                        Error::Noise(format!(
                            "Failed to build HandshakeState for initiator: {:?}",
                            e
                        ))
                    })?;
                Ok(ChannelBuilder {
                    handshake_state: handshake_state,
                    state: State::Init,
                })
            }
        } else {
            if channel_inputs.remote_public_key.is_none() {
                return Err(Error::Noise(format!(
                    "Responder must know the remote public key for initiator"
                )));
            }

            let handshake_state = noise_builder
                .local_private_key(&channel_inputs.authentication_key.0)
                .remote_public_key(&channel_inputs.remote_public_key.unwrap().0)
                .build_responder()
                .map_err(|e| {
                    Error::Noise(format!(
                        "Failed to build HandshakeState for responder: {:?}",
                        e
                    ))
                })?;
            Ok(ChannelBuilder {
                handshake_state: handshake_state,
                state: State::Init,
            })
        }
    }

    /// Returns msg A for client to send to server
    pub fn client_write_msg_a(&mut self) -> Result<Vec<u8>, Error> {
        if self.state != State::Init {
            return Err(Error::Noise(format!(
                "Invalid function call sequence for handshake"
            )));
        }

        let mut msg_buf = vec![0_u8; NOISE_MESSAGE_MAX_SIZE];
        let len = self
            .handshake_state
            .write_message(&[0u8; 0], &mut msg_buf)
            .map_err(|e| Error::Noise(format!("Client failed to write message A: {:?}", e)))?;
        msg_buf.truncate(len);
        self.state = State::ClientSentMessageA;
        Ok(msg_buf)
    }

    /// Server reads msg A
    pub fn server_read_msg_a(&mut self, message: &[u8]) -> Result<(), Error> {
        if self.state != State::Init {
            return Err(Error::Noise(format!(
                "Invalid function call sequence for handshake"
            )));
        }

        if message.len() < NOISE_MESSAGE_MIN_SIZE || message.len() > NOISE_MESSAGE_MAX_SIZE {
            return Err(Error::Noise(format!("Invalid message length")));
        }

        let mut _buf = vec![0_u8; NOISE_MESSAGE_MAX_SIZE];
        let _len = self
            .handshake_state
            .read_message(&message, &mut _buf)
            .map_err(|e| Error::Noise(format!("Server failed to read message A: {:?}", e)))?;
        self.state = State::ServerRecievedMessageA;
        Ok(())
    }

    /// Returns msg B to send to client
    pub fn server_write_msg_b(&mut self) -> Result<Vec<u8>, Error> {
        if self.state != State::ServerRecievedMessageA {
            return Err(Error::Noise(format!(
                "Invalid function call sequence for handshake"
            )));
        }

        let mut msg_buf = vec![0_u8; NOISE_MESSAGE_MAX_SIZE];
        let len = self
            .handshake_state
            .write_message(&[0u8; 0], &mut msg_buf)
            .map_err(|e| Error::Noise(format!("Server failed to write message B: {:?}", e)))?;
        msg_buf.truncate(len);
        self.state = State::ServerSentMessageB;
        Ok(msg_buf)
    }

    /// Client reads msg B
    pub fn client_read_msg_b(&mut self, message: &[u8]) -> Result<(), Error> {
        if self.state != State::ClientSentMessageA {
            return Err(Error::Noise(format!(
                "Invalid function call sequence for handshake"
            )));
        }
        let mut _buf = [0u8; NOISE_MESSAGE_MAX_SIZE];
        let _len = self
            .handshake_state
            .read_message(&message, &mut _buf)
            .map_err(|e| Error::Noise(format!("Client failed to read message B: {:?}", e)))?;
        self.state = State::ClientRecievedMessageB;
        Ok(())
    }

    /// Convert the ChannelBuilder into a secure Channel; transition into transport
    /// mode after handshake is finished.
    pub fn into_channel(self) -> Result<Channel, Error> {
        if self.state != State::ClientRecievedMessageB && self.state != State::ServerSentMessageB {
            return Err(Error::Noise(format!(
                "Handshake is not complete, cannot transition to transport mode."
            )));
        }

        let transport_state = self
            .handshake_state
            .into_transport_mode()
            .map_err(|e| Error::Noise(format!("Failed to enter transport mode: {:?}", e)))?;

        Ok(Channel {
            transport_state: transport_state,
        })
    }
}

/// Channel can be used to encrypt and decrypt payloads. It can only be constructed
/// through a successful handshake using the ChannelBuilder.
#[derive(Debug)]
pub struct Channel {
    transport_state: TransportState,
}

impl Channel {
    /// Use the channel to encrypt any given message. Pre-fixes the message with
    /// (big-endian) length field and pads the message with 0s before encryption.
    /// On success, returns the ciphertext.
    pub fn encrypt_message(&mut self, message: &[u8]) -> Result<Vec<u8>, Error> {
        // Prefix
        let message_len: usize = MAC_SIZE + message.len();
        if message_len > NOISE_MESSAGE_MAX_SIZE {
            return Err(Error::Noise(format!("Message is too large to encrypt")));
        }
        let header: [u8; 8] = message_len.to_be_bytes();
        let mut ciphertext_header = [0_u8; NOISE_MESSAGE_HEADER_SIZE];
        let _ct_header_len = self
            .transport_state
            .write_message(&header, &mut ciphertext_header)
            .map_err(|e| Error::Noise(format!("Header encryption failed: {:?}", e)))?;

        // Pad message
        let mut message_body = Vec::new();
        message_body.extend_from_slice(message);
        while message_body.len() < NOISE_PADDED_MESSAGE_SIZE {
            message_body.extend_from_slice(&[0u8; 1]);
        }

        // Encrypt message
        let mut ciphertext = vec![0_u8; NOISE_MESSAGE_MAX_SIZE];
        let ciphertext_len = self
            .transport_state
            .write_message(&message_body[..], &mut ciphertext)
            .map_err(|e| Error::Noise(format!("Message encryption failed: {:?}", e)))?;
        ciphertext.truncate(ciphertext_len);

        let mut output = Vec::new();
        output.extend_from_slice(&ciphertext_header);
        output.extend_from_slice(&ciphertext[..]);
        Ok(output)
    }

    /// Decrypts the message header and returns the length of the unpadded message.
    pub fn decrypt_message_header(&mut self, message: &[u8]) -> Result<usize, Error> {
        let mut header = [0_u8; 8];
        let header_len = self
            .transport_state
            .read_message(&message[..NOISE_MESSAGE_HEADER_SIZE], &mut header)
            .map_err(|e| Error::Noise(format!("Failed to decrypt message header: {:?}", e)))?;
        let message_len = usize::from_be_bytes(header) - MAC_SIZE;
        Ok(message_len)
    }

    /// Given the length of the unpadded message, decrypts the message.
    /// On success returns the plaintext message.
    pub fn decrypt_message(&mut self, message: &[u8], msg_len: usize) -> Result<Vec<u8>, Error> {
        let mut plaintext = vec![0_u8; NOISE_MESSAGE_MAX_SIZE];
        let padded_len = self
            .transport_state
            .read_message(&message, &mut plaintext)
            .map_err(|e| Error::Noise(format!("Failed to decrypt message: {:?}", e)))?;
        if padded_len != NOISE_PADDED_MESSAGE_SIZE {
            return Err(Error::Noise(format!(
                "Decrypted message does not have expected size"
            )));
        }
        plaintext.truncate(msg_len);
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snow::Keypair;

    /// Revault must specify the SodiumResolver to use sodiumoxide as the cryptography provider
    /// when generating a static key pair for secure communication.
    pub fn generate_keypair(noise_params: NoiseParams) -> Keypair {
        Builder::with_resolver(noise_params, Box::new(SodiumResolver::default()))
            .generate_keypair()
            .unwrap()
    }

    fn compare_vecs<T: PartialEq>(a: &Vec<T>, b: &Vec<T>) -> bool {
        let matching = a.iter().zip(b.iter()).filter(|&(a, b)| a == b).count();
        matching == a.len() && matching == b.len()
    }

    #[test]
    fn test_kk_handshake_encrypted_transport() {
        let noise_params: NoiseParams = "Noise_KK_25519_ChaChaPoly_SHA256".parse().unwrap();
        let client_keypair = generate_keypair(noise_params.clone());
        let server_keypair = generate_keypair(noise_params);

        // client
        let authentication_key = NoiseKey::from_vec(client_keypair.private).unwrap();
        let remote_public_key = NoiseKey::from_vec(server_keypair.public).unwrap();

        let client_channel_inputs = ChannelInputs {
            authentication_key: authentication_key,
            remote_public_key: Some(remote_public_key),
            handshake_choice: HandshakeChoice::Kk,
            is_initiator: true,
        };
        let mut client_channel_builder = ChannelBuilder::new(client_channel_inputs).unwrap();

        // server
        let authentication_key = NoiseKey::from_vec(server_keypair.private).unwrap();
        let remote_public_key = NoiseKey::from_vec(client_keypair.public).unwrap();

        let server_channel_inputs = ChannelInputs {
            authentication_key: authentication_key,
            remote_public_key: Some(remote_public_key),
            handshake_choice: HandshakeChoice::Kk,
            is_initiator: false,
        };
        let mut server_channel_builder = ChannelBuilder::new(server_channel_inputs).unwrap();

        // message A
        let msg_a = client_channel_builder.client_write_msg_a().unwrap();
        // client sends msg A to server...
        server_channel_builder.server_read_msg_a(&msg_a).unwrap();
        let msg_b = server_channel_builder.server_write_msg_b().unwrap();
        let mut server_channel = server_channel_builder.into_channel().unwrap();
        // server responds to client with msg B...
        client_channel_builder.client_read_msg_b(&msg_b).unwrap();
        let mut client_channel = client_channel_builder.into_channel().unwrap();

        // test client sending encrypted message to server and decrypting.
        let plaintext = "Hello".as_bytes();
        let ciphertext = client_channel.encrypt_message(&plaintext).unwrap();

        // client sends ciphertext to server...
        let len = server_channel
            .decrypt_message_header(&ciphertext[..NOISE_MESSAGE_HEADER_SIZE])
            .unwrap();
        let decrypted_message = server_channel
            .decrypt_message(&ciphertext[NOISE_MESSAGE_HEADER_SIZE..], len)
            .unwrap();

        assert!(compare_vecs(&plaintext.to_vec(), &decrypted_message));
    }

    #[test]
    fn test_kx_handshake_encrypted_transport() {
        let noise_params: NoiseParams = "Noise_KX_25519_ChaChaPoly_SHA256".parse().unwrap();
        let client_keypair = generate_keypair(noise_params.clone());
        let server_keypair = generate_keypair(noise_params);

        // client
        let authentication_key = NoiseKey::from_vec(client_keypair.private).unwrap();
        let remote_public_key = NoiseKey::from_vec(server_keypair.public).unwrap();

        let client_channel_inputs = ChannelInputs {
            authentication_key: authentication_key,
            remote_public_key: Some(remote_public_key),
            handshake_choice: HandshakeChoice::Kx,
            is_initiator: true,
        };
        let mut client_channel_builder = ChannelBuilder::new(client_channel_inputs).unwrap();

        // server
        let authentication_key = NoiseKey::from_vec(server_keypair.private).unwrap();
        let remote_public_key = NoiseKey::from_vec(client_keypair.public).unwrap();

        let server_channel_inputs = ChannelInputs {
            authentication_key: authentication_key,
            remote_public_key: Some(remote_public_key),
            handshake_choice: HandshakeChoice::Kx,
            is_initiator: false,
        };
        let mut server_channel_builder = ChannelBuilder::new(server_channel_inputs).unwrap();

        // message A
        let msg_a = client_channel_builder.client_write_msg_a().unwrap();
        // client sends msg A to server...
        server_channel_builder.server_read_msg_a(&msg_a).unwrap();
        let msg_b = server_channel_builder.server_write_msg_b().unwrap();
        let mut server_channel = server_channel_builder.into_channel().unwrap();
        // server responds to client with msg B...
        client_channel_builder.client_read_msg_b(&msg_b).unwrap();
        let mut client_channel = client_channel_builder.into_channel().unwrap();

        // test client sending encrypted message to server and decrypting.
        let plaintext = [0u8; NOISE_PADDED_MESSAGE_SIZE];
        let ciphertext = client_channel.encrypt_message(&plaintext).unwrap();

        // client sends ciphertext to server...
        let len = server_channel
            .decrypt_message_header(&ciphertext[..NOISE_MESSAGE_HEADER_SIZE])
            .unwrap();
        let decrypted_message = server_channel
            .decrypt_message(&ciphertext[NOISE_MESSAGE_HEADER_SIZE..], len)
            .unwrap();

        assert!(compare_vecs(&plaintext.to_vec(), &decrypted_message));
    }
}
