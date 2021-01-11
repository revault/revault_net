//! Noise Protocol Framework API
//!
//! This module is a wrapper for noise functionality provided by snow to build
//! and use secure communication channels between revault infrastructure machines.
//!

use crate::error::Error;
use revault_tx::bitcoin::hashes::hex::FromHex;

use std::{convert::TryInto, str::FromStr};

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
/// Maximum size of a message before being encrypted; limited by Noise Protocol Framework
pub const NOISE_PLAINTEXT_MAX_SIZE: usize = NOISE_MESSAGE_MAX_SIZE - NOISE_MESSAGE_HEADER_SIZE;
/// e, es, ss
pub const KK_MSG_1_SIZE: usize = KEY_SIZE + HANDSHAKE_MESSAGE.len() + MAC_SIZE;
/// e, ee, se
pub const KK_MSG_2_SIZE: usize = KEY_SIZE + MAC_SIZE;
/// Sent for versioning and identification during handshake
pub const HANDSHAKE_MESSAGE: &[u8] = b"practical_revault_0";

/// A static Noise public key
#[derive(Debug, Copy, Clone)]
pub struct NoisePubKey(pub [u8; KEY_SIZE]);

impl FromStr for NoisePubKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(
            FromHex::from_hex(s).map_err(|e| Error::Noise(e.to_string()))?,
        ))
    }
}

/// A static Noise private key
#[derive(Debug)]
pub struct NoisePrivKey(pub [u8; KEY_SIZE]);

/// First round of the KK handshake
#[derive(Debug)]
pub struct KKHandshakeActOne {
    state: HandshakeState,
}

/// Message sent during the first round of the KK handshake (e, es, ss)
#[derive(Debug)]
pub struct KKMessageActOne(pub(crate) [u8; KK_MSG_1_SIZE]);

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
            Box::new(SodiumResolver::default()),
        );
        let mut state = builder
            .local_private_key(&my_privkey.0)
            .remote_public_key(&their_pubkey.0)
            .build_initiator()
            .map_err(|e| Error::Noise(format!("Failed to build state for initiator: {:?}", e)))?;

        // Write the first message
        let mut msg = [0u8; KK_MSG_1_SIZE];
        state
            .write_message(HANDSHAKE_MESSAGE, &mut msg)
            .map_err(|e| {
                Error::Noise(format!(
                    "Failed to write first message for initiator: {:?}",
                    e
                ))
            })?;

        Ok((KKHandshakeActOne { state }, KKMessageActOne(msg)))
    }

    /// Start the first act of the handshake as a responder (reading e, es, ss and doing wizardry with it)
    pub fn responder(
        my_privkey: &NoisePrivKey,
        their_possible_pubkeys: &[NoisePubKey],
        message: &KKMessageActOne,
    ) -> Result<KKHandshakeActOne, Error> {
        // TODO: estimate how inefficient it is.
        for their_pubkey in their_possible_pubkeys {
            // Build the initial responder state
            let builder = Builder::with_resolver(
                "Noise_KK_25519_ChaChaPoly_SHA256"
                    .parse()
                    .expect("Valid params"),
                Box::new(SodiumResolver::default()),
            );
            let mut state = builder
                .local_private_key(&my_privkey.0)
                .remote_public_key(&their_pubkey.0)
                .build_responder()
                .map_err(|e| {
                    Error::Noise(format!("Failed to build state for responder: {:?}", e))
                })?;

            let mut msg = [0u8; KK_MSG_1_SIZE];
            if state.read_message(&message.0, &mut msg).is_err() {
                continue;
            }
            if &msg[..HANDSHAKE_MESSAGE.len()] != HANDSHAKE_MESSAGE {
                return Err(Error::Noise(format!(
                    "Wrong handshake message. Expected '{:x?}' got '{:x?}'.",
                    HANDSHAKE_MESSAGE,
                    &msg[..HANDSHAKE_MESSAGE.len()]
                )));
            }

            return Ok(KKHandshakeActOne { state });
        }

        Err(Error::Noise("No matching pubkey".to_string()))
    }
}

/// Final round of the KK handshake
#[derive(Debug)]
pub struct KKHandshakeActTwo {
    /// Inner snow Noise KK handshake state
    state: HandshakeState,
}

/// Content of the message from the final round of the KK handshake (e, ee, se)
#[derive(Debug)]
pub struct KKMessageActTwo(pub(crate) [u8; KK_MSG_2_SIZE]);

impl KKHandshakeActTwo {
    /// Start the second act of the handshake as a responder (read e, ee, se)
    pub fn initiator(
        mut handshake: KKHandshakeActOne,
        message: &KKMessageActTwo,
    ) -> Result<KKHandshakeActTwo, Error> {
        // In handshake mode we don't actually care about the message
        let mut _m = [0u8; KK_MSG_2_SIZE];
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
        let mut msg = [0u8; KK_MSG_2_SIZE];
        handshake.state.write_message(&[], &mut msg).map_err(|e| {
            Error::Noise(format!("Responder failed to write second message: {:?}", e))
        })?;

        Ok((
            KKHandshakeActTwo {
                state: handshake.state,
            },
            KKMessageActTwo(msg),
        ))
    }
}

/// A cyphertext encrypted with [encrypt_message]
#[derive(Debug)]
pub struct NoiseEncryptedMessage(pub Vec<u8>);

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

    /// Use the channel to encrypt a message shorter than [NOISE_MESSAGE_HEADER_SIZE].
    /// Pre-fixes the message with (big-endian) length field and pads the message with
    /// 0s before encryption.
    /// On success, returns the ciphertext.
    pub fn encrypt_message(&mut self, message: &[u8]) -> Result<NoiseEncryptedMessage, Error> {
        if message.len() > NOISE_PLAINTEXT_MAX_SIZE {
            return Err(Error::Noise("Message is too large to encrypt".to_string()));
        }
        let mut output = vec![0u8; NOISE_MESSAGE_HEADER_SIZE + message.len()];

        let message_len: usize = MAC_SIZE + message.len();
        let mut prefixed_message = message_len.to_be_bytes().to_vec();
        prefixed_message.extend_from_slice(message);
        self.transport_state
            .write_message(&prefixed_message, &mut output)
            .map_err(|e| Error::Noise(format!("Header encryption failed: {:?}", e)))?;

        Ok(NoiseEncryptedMessage(output))
    }

    /// Get plaintext bytes from a valid Noise-encrypted message
    pub fn decrypt_message(&mut self, message: &NoiseEncryptedMessage) -> Result<Vec<u8>, Error> {
        // TODO: could be in NoiseEncryptedMessage's constructor?
        if message.0.len() > NOISE_MESSAGE_MAX_SIZE {
            return Err(Error::Noise("Message is too large to decrypt".to_string()));
        }
        if message.0.len() < NOISE_MESSAGE_HEADER_SIZE {
            return Err(Error::Noise("Message is too small to decrypt".to_string()));
        }
        let mut output = vec![0u8; message.0.len()];

        self.transport_state
            .read_message(&message.0, &mut output)
            .map_err(|e| Error::Noise(format!("Failed to decrypt message: {:?}", e)))?;

        // We read the length prefix and the MAC, but we don't care about any of both (we use a
        // vec, and the MAC is checked by Snow).
        // TODO: bench this against truncating and reverse-then-pop-then-reverse
        Ok(output
            .drain(LENGTH_PREFIX_SIZE..output.len() - MAC_SIZE)
            .collect())
    }

    /// Get the static public key of the peer
    pub fn remote_static(&self) -> NoisePubKey {
        NoisePubKey(
            self.transport_state
                .get_remote_static()
                .expect(
                    "We could not have settled the KK channel without their key. \
                     And if we could, better to crash now!",
                )
                .try_into()
                .expect("Our keys aren't 32 bytes anymore?"),
        )
    }
}

#[cfg(test)]
pub mod tests {
    use crate::{
        error::Error,
        noise::{
            KKChannel, KKHandshakeActOne, KKHandshakeActTwo, KKMessageActOne, KKMessageActTwo,
            NoiseEncryptedMessage, NoisePrivKey, NoisePubKey, KK_MSG_1_SIZE, KK_MSG_2_SIZE,
            NOISE_MESSAGE_HEADER_SIZE, NOISE_MESSAGE_MAX_SIZE, NOISE_PLAINTEXT_MAX_SIZE,
        },
    };
    use snow::{params::NoiseParams, resolvers::SodiumResolver, Builder, Keypair};
    use std::{convert::TryInto, str::FromStr};

    #[derive(Debug, Clone)]
    pub enum HandshakeChoice {
        Kx,
        Kk,
    }

    pub fn get_noise_params(hs_choice: &HandshakeChoice) -> Result<NoiseParams, Error> {
        let noise_params: NoiseParams = match hs_choice {
            HandshakeChoice::Kk => "Noise_KK_25519_ChaChaPoly_SHA256"
                .parse()
                .map_err(|e| Error::Noise(format!("Invalid Noise Pattern: {}", e)))?,
            HandshakeChoice::Kx => "Noise_KX_25519_ChaChaPoly_SHA256"
                .parse()
                .map_err(|e| Error::Noise(format!("Invalid Noise Pattern: {}", e)))?,
        };
        Ok(noise_params)
    }

    /// Revault must specify the SodiumResolver to use sodiumoxide as the cryptography provider
    /// when generating a static key pair for secure communication.
    pub fn generate_keypair(noise_params: NoiseParams) -> Keypair {
        Builder::with_resolver(noise_params, Box::new(SodiumResolver::default()))
            .generate_keypair()
            .unwrap()
    }

    #[test]
    fn test_kk_handshake_encrypted_transport() {
        let hs_choice = HandshakeChoice::Kk;
        let noise_params = get_noise_params(&hs_choice).unwrap();

        // key gen
        let initiator_keypair = generate_keypair(noise_params.clone());
        let initiator_privkey = NoisePrivKey(initiator_keypair.private[..].try_into().unwrap());
        let initiator_pubkey = NoisePubKey(initiator_keypair.public[..].try_into().unwrap());

        let responder_keypair = generate_keypair(noise_params);
        let responder_privkey = NoisePrivKey(responder_keypair.private[..].try_into().unwrap());
        let responder_pubkey = NoisePubKey(responder_keypair.public[..].try_into().unwrap());

        // client
        let (cli_act_1, msg_1) =
            KKHandshakeActOne::initiator(&initiator_privkey, &responder_pubkey).unwrap();

        // server
        let serv_act_1 =
            KKHandshakeActOne::responder(&responder_privkey, &[initiator_pubkey], &msg_1).unwrap();
        let (serv_act_2, msg_2) = KKHandshakeActTwo::responder(serv_act_1).unwrap();
        let mut server_channel = KKChannel::from_handshake(serv_act_2).unwrap();

        // client
        let cli_act_2 = KKHandshakeActTwo::initiator(cli_act_1, &msg_2).unwrap();
        let mut client_channel = KKChannel::from_handshake(cli_act_2).unwrap();

        // client encrypts message for server
        let msg = "Hello".as_bytes();
        let encrypted_msg = client_channel.encrypt_message(&msg).unwrap();
        let decrypted_msg = server_channel.decrypt_message(&encrypted_msg).unwrap();
        assert_eq!(msg.to_vec(), decrypted_msg);

        // server encrypts message for client
        let msg = "Goodbye".as_bytes();
        let encrypted_msg = server_channel.encrypt_message(&msg).unwrap();
        let decrypted_msg = client_channel.decrypt_message(&encrypted_msg).unwrap();
        assert_eq!(msg.to_vec(), decrypted_msg);
    }

    #[test]
    fn test_message_size_limit() {
        let hs_choice = HandshakeChoice::Kx;
        let noise_params = get_noise_params(&hs_choice).unwrap();

        // key gen
        let initiator_keypair = generate_keypair(noise_params.clone());
        let initiator_privkey = NoisePrivKey(initiator_keypair.private[..].try_into().unwrap());
        let initiator_pubkey = NoisePubKey(initiator_keypair.public[..].try_into().unwrap());

        let responder_keypair = generate_keypair(noise_params);
        let responder_privkey = NoisePrivKey(responder_keypair.private[..].try_into().unwrap());
        let responder_pubkey = NoisePubKey(responder_keypair.public[..].try_into().unwrap());

        // client
        let (_, msg_1) =
            KKHandshakeActOne::initiator(&initiator_privkey, &responder_pubkey).unwrap();

        // server
        let serv_act_1 =
            KKHandshakeActOne::responder(&responder_privkey, &[initiator_pubkey], &msg_1).unwrap();
        let (serv_act_2, _msg_2) = KKHandshakeActTwo::responder(serv_act_1).unwrap();
        let mut server_channel = KKChannel::from_handshake(serv_act_2).unwrap();

        // Hit the limit
        let msg = [0u8; NOISE_PLAINTEXT_MAX_SIZE];
        server_channel
            .encrypt_message(&msg)
            .expect("Maximum allowed");

        // Fail if msg too large
        let msg = [0u8; NOISE_MESSAGE_MAX_SIZE - NOISE_MESSAGE_HEADER_SIZE + 1];
        server_channel
            .encrypt_message(&msg)
            .expect_err("Limit exceeded");

        // We can encrypt an empty message
        let msg = b"";
        server_channel
            .encrypt_message(msg)
            .expect("Empty message is fine to encrypt");

        // We cannot decrypt an empty message
        server_channel
            .decrypt_message(&NoiseEncryptedMessage(msg.to_vec()))
            .expect_err("Encrypted message with no header");
    }

    #[test]
    fn test_bad_messages() {
        let hs_choice = HandshakeChoice::Kk;
        let noise_params = get_noise_params(&hs_choice).unwrap();

        // key gen
        let initiator_keypair = generate_keypair(noise_params.clone());
        let initiator_privkey = NoisePrivKey(initiator_keypair.private[..].try_into().unwrap());
        let initiator_pubkey = NoisePubKey(initiator_keypair.public[..].try_into().unwrap());

        let responder_keypair = generate_keypair(noise_params);
        let responder_privkey = NoisePrivKey(responder_keypair.private[..].try_into().unwrap());
        let responder_pubkey = NoisePubKey(responder_keypair.public[..].try_into().unwrap());

        // KK handshake fails if messages are badly formed.
        // Without a valid cli_act_2 nor serv_act_2, no KKChannel can be constructed.
        let (cli_act_1, _) = KKHandshakeActOne::initiator(&initiator_privkey, &responder_pubkey)
            .expect("The first act is valid.");

        let bad_msg = KKMessageActOne([1u8; KK_MSG_1_SIZE]);
        KKHandshakeActOne::responder(&responder_privkey, &[initiator_pubkey], &bad_msg)
            .expect_err("This one is invalid as bad_msg cannot be decrypted.");

        let bad_msg = KKMessageActTwo([1u8; KK_MSG_2_SIZE]);
        KKHandshakeActTwo::initiator(cli_act_1, &bad_msg).expect_err("So is this one.");
    }

    #[test]
    fn test_pubkey_from_str() {
        NoisePubKey::from_str("61feafb2db96bf650b496c74c24ce92fa608e271b4092405f3364c9f8466df66")
            .expect("Parsing an invalid but well-encoded pubkey");
    }
}
