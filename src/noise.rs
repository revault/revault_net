use crate::error::Error;
use byteorder::{BigEndian, ByteOrder};
use snow::{
    params::NoiseParams, resolvers::SodiumResolver, Builder, HandshakeState, TransportState,
};
use std::convert::TryFrom;

pub const KEY_SIZE: usize = 32;
pub const MAC_SIZE: usize = 16;
pub const NOISE_MESSAGE_MAX_SIZE: usize = 65535;
pub const NOISE_MESSAGE_MIN_SIZE: usize = KEY_SIZE;
pub const NOISE_MESSAGE_HEADER_SIZE: usize = MAC_SIZE + 4;

#[derive(PartialEq, Debug, Clone)]
pub enum State {
    Init,
    ClientSentMessageA,
    ServerRecievedMessageA,
    ServerSentMessageB,
    ClientRecievedMessageB,
    DataTransfer,
}

#[derive(PartialEq, Debug, Clone)]
pub enum HandshakeChoice {
    Kx,
    Kk,
}

/// A session configuration type.
#[derive(PartialEq, Debug, Clone)]
pub struct SessionConfig {
    // Key used to authenticate and encrypt noise messages
    authentication_key: Vec<u8>,
    // Static public key of remote peer
    remote_public_key: Option<Vec<u8>>,
    // Handshake choice for this session
    handshake_choice: HandshakeChoice,
}

#[derive(Debug)]
pub struct MessageBuilder {
    handshake_state: Option<HandshakeState>,
    transport_state: Option<TransportState>,
    state: State,
    is_initiator: bool,
}

/// Clients and Servers can use MessageBuilder to enact a noise handshake and
/// establish a secure channel. Then, the message builder can be used to encrypt
/// and decrypt payloads.
impl MessageBuilder {
    pub fn new(config: SessionConfig, is_initiator: bool) -> Result<MessageBuilder, Error> {
        let noise_params: NoiseParams = match config.handshake_choice {
            HandshakeChoice::Kk => "Noise_KK_25519_ChaChaPoly_SHA256"
                .parse()
                .map_err(|e| Error::Noise(format!("Invalid Noise Pattern: {}", e)))?,
            HandshakeChoice::Kx => "Noise_KX_25519_ChaChaPoly_SHA256"
                .parse()
                .map_err(|e| Error::Noise(format!("Invalid Noise Pattern: {}", e)))?,
        };

        let noise_builder: Builder =
            Builder::with_resolver(noise_params, Box::new(SodiumResolver::default()));

        if is_initiator {
            // Don't always have pubkey for remote
            if config.remote_public_key.is_none() {
                let handshake_state = match noise_builder
                    .local_private_key(&config.authentication_key)
                    .build_initiator()
                {
                    Ok(x) => x,
                    Err(_) => {
                        return Err(Error::Noise(format!(
                            "Failed to build HandshakeState for initiator"
                        )))
                    }
                };
                return Ok(MessageBuilder {
                    handshake_state: Some(handshake_state),
                    transport_state: None,
                    state: State::Init,
                    is_initiator,
                });
            } else {
                let handshake_state = match noise_builder
                    .local_private_key(&config.authentication_key)
                    .remote_public_key(&config.remote_public_key.unwrap())
                    .build_initiator()
                {
                    Ok(x) => x,
                    Err(_) => {
                        return Err(Error::Noise(format!(
                            "Failed to build HandshakeState for initiator"
                        )))
                    }
                };
                return Ok(MessageBuilder {
                    handshake_state: Some(handshake_state),
                    transport_state: None,
                    state: State::Init,
                    is_initiator,
                });
            }
        } else {
            if config.remote_public_key.is_none() {
                return Err(Error::Noise(format!(
                    "Responder must know the remote public key for initiator"
                )));
            }

            let handshake_state = match noise_builder
                .local_private_key(&config.authentication_key)
                .remote_public_key(&config.remote_public_key.unwrap())
                .build_responder()
            {
                Ok(x) => x,
                Err(_) => {
                    return Err(Error::Noise(format!(
                        "Failed to build HandshakeState for responder"
                    )))
                }
            };
            Ok(MessageBuilder {
                handshake_state: Some(handshake_state),
                transport_state: None,
                state: State::Init,
                is_initiator,
            })
        }
    }

    pub fn client_write_msg_a(&mut self) -> Result<Vec<u8>, Error> {
        if self.state != State::Init {
            return Err(Error::Noise(format!(
                "Invalid function call sequence for handshake"
            )));
        }

        let mut msg_buf = vec![0_u8; NOISE_MESSAGE_MAX_SIZE];
        let len = match self
            .handshake_state
            .as_mut()
            .unwrap()
            .write_message(&[0u8; 0], &mut msg_buf)
        {
            Ok(x) => x,
            Err(_) => return Err(Error::Noise(format!("Client failed to write message A"))),
        };
        msg_buf.truncate(len);
        self.state = State::ClientSentMessageA;
        Ok(msg_buf)
    }

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
        let _len = match self
            .handshake_state
            .as_mut()
            .unwrap()
            .read_message(&message, &mut _buf)
        {
            Ok(x) => x,
            Err(_) => return Err(Error::Noise(format!("Server failed to read message A"))),
        };

        self.state = State::ServerRecievedMessageA;
        Ok(())
    }

    pub fn server_write_msg_b(&mut self) -> Result<Vec<u8>, Error> {
        if self.state != State::ServerRecievedMessageA {
            return Err(Error::Noise(format!(
                "Invalid function call sequence for handshake"
            )));
        }

        let mut msg_buf = vec![0_u8; NOISE_MESSAGE_MAX_SIZE];
        let len = match self
            .handshake_state
            .as_mut()
            .unwrap()
            .write_message(&[0u8; 0], &mut msg_buf)
        {
            Ok(x) => x,
            Err(_) => return Err(Error::Noise(format!("Server failed to write message B"))),
        };
        msg_buf.truncate(len);
        self.state = State::ServerSentMessageB;
        Ok(msg_buf)
    }

    pub fn client_read_msg_b(&mut self, message: &[u8]) -> Result<(), Error> {
        if self.state != State::ClientSentMessageA {
            return Err(Error::Noise(format!(
                "Invalid function call sequence for handshake"
            )));
        }
        let mut _buf = [0u8; NOISE_MESSAGE_MAX_SIZE];
        let _len = match self
            .handshake_state
            .as_mut()
            .unwrap()
            .read_message(&message, &mut _buf)
        {
            Ok(x) => x,
            Err(_) => return Err(Error::Noise(format!("Client failed to read message B"))),
        };
        self.state = State::ClientRecievedMessageB;
        Ok(())
    }

    pub fn into_transport_mode(self) -> Result<Self, Error> {
        if self.is_initiator {
            if self.state != State::ClientRecievedMessageB {
                return Err(Error::Noise(format!(
                    "Handshake is not complete, cannot transition to transport mode."
                )));
            }
        } else {
            if self.state != State::ServerSentMessageB {
                return Err(Error::Noise(format!(
                    "Handshake is not complete, cannot transition to transport mode."
                )));
            }
        }

        let transport_state = self
            .handshake_state
            .unwrap()
            .into_transport_mode()
            .map_err(|e| Error::Noise(format!("Failed to enter transport mode: {:?}", e)))?;

        // Transition into transport mode after handshake is finished.
        Ok(Self {
            handshake_state: None,
            transport_state: Some(transport_state),
            state: State::DataTransfer,
            is_initiator: self.is_initiator,
        })
    }

    pub fn encrypt_message(&mut self, message: &[u8]) -> Result<Vec<u8>, Error> {
        // Prefix clear text message with it's length
        let ct_len = MAC_SIZE + message.len();
        if ct_len > NOISE_MESSAGE_MAX_SIZE {
            return Err(Error::Noise(format!("Message is too large to encrypt")));
        }
        let mut ct_hdr = [0u8; 4];
        BigEndian::write_u32(&mut ct_hdr, ct_len as u32);
        let mut ciphertext_header = [0u8; NOISE_MESSAGE_MAX_SIZE];
        let header_len = match self
            .transport_state
            .as_mut()
            .unwrap()
            .write_message(&ct_hdr, &mut ciphertext_header)
        {
            Ok(len) => len,
            Err(_) => return Err(Error::Noise(format!("Header encryption failed"))),
        };

        let mut ciphertext = [0u8; NOISE_MESSAGE_MAX_SIZE];
        let payload_len = match self
            .transport_state
            .as_mut()
            .unwrap()
            .write_message(&message, &mut ciphertext)
        {
            Ok(len) => len,
            Err(_) => return Err(Error::Noise(format!("Message encryption failed"))),
        };
        let mut output = Vec::new();
        output.extend_from_slice(&ciphertext_header[..header_len]);
        output.extend_from_slice(&ciphertext[..payload_len]);
        Ok(output)
    }

    pub fn decrypt_message_header(&mut self, message: &[u8]) -> Result<u32, Error> {
        let mut header = [0u8; NOISE_MESSAGE_MAX_SIZE];
        match self
            .transport_state
            .as_mut()
            .unwrap()
            .read_message(&message[..NOISE_MESSAGE_HEADER_SIZE], &mut header)
        {
            Ok(x) => {
                assert_eq!(x, 4);
                Ok(BigEndian::read_u32(&header[..NOISE_MESSAGE_HEADER_SIZE]))
            }
            Err(_) => Err(Error::Noise(format!("Failed to decrypt message header"))),
        }
    }

    pub fn decrypt_message(&mut self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let mut plaintext = [0u8; NOISE_MESSAGE_MAX_SIZE];
        match self
            .transport_state
            .as_mut()
            .unwrap()
            .read_message(&message, &mut plaintext)
        {
            Ok(len) => Ok(plaintext[..len].to_vec()),
            Err(_) => Err(Error::Noise(format!("Failed to decrypt message"))),
        }
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

    #[test]
    fn test_kk_handshake_encrypted_transport() {
        let noise_params: NoiseParams = "Noise_KK_25519_ChaChaPoly_SHA256".parse().unwrap();
        let client_keypair = generate_keypair(noise_params.clone());
        let server_keypair = generate_keypair(noise_params);

        // client
        let client_config = SessionConfig {
            authentication_key: client_keypair.private,
            remote_public_key: Some(server_keypair.public),
            handshake_choice: HandshakeChoice::Kk,
        };
        let mut client_session = MessageBuilder::new(client_config, true).unwrap();

        // server
        let server_config = SessionConfig {
            authentication_key: server_keypair.private,
            remote_public_key: Some(client_keypair.public),
            handshake_choice: HandshakeChoice::Kk,
        };
        let mut server_session = MessageBuilder::new(server_config, false).unwrap();

        // message A
        let msg_a = client_session.client_write_msg_a().unwrap();
        // client sends msg A to server
        server_session.server_read_msg_a(&msg_a).unwrap();
        let msg_b = server_session.server_write_msg_b().unwrap();
        server_session = server_session.into_transport_mode().unwrap();
        // server responds to client with msg B
        client_session.client_read_msg_b(&msg_b).unwrap();
        client_session = client_session.into_transport_mode().unwrap();

        // test client sending encrypted message to server and decrypting.
        let plaintext = "Hello".as_bytes();
        let ciphertext = client_session.encrypt_message(&plaintext).unwrap();
        // client sends ciphertext to server...
        let ct_len = server_session
            .decrypt_message_header(&ciphertext[..NOISE_MESSAGE_HEADER_SIZE])
            .unwrap() as usize;
        assert_eq!(ct_len, MAC_SIZE + plaintext.len());
        let decrypted_message = server_session
            .decrypt_message(&ciphertext[NOISE_MESSAGE_HEADER_SIZE..])
            .unwrap();
        assert_eq!(decrypted_message, plaintext);
    }

    #[test]
    fn test_kx_handshake_encrypted_transport() {
        let noise_params: NoiseParams = "Noise_KX_25519_ChaChaPoly_SHA256".parse().unwrap();
        let client_keypair = generate_keypair(noise_params.clone());
        let server_keypair = generate_keypair(noise_params);

        // client
        let client_config = SessionConfig {
            authentication_key: client_keypair.private,
            remote_public_key: None,
            handshake_choice: HandshakeChoice::Kx,
        };
        let mut client_session = MessageBuilder::new(client_config, true).unwrap();

        // server
        let server_config = SessionConfig {
            authentication_key: server_keypair.private,
            remote_public_key: Some(client_keypair.public),
            handshake_choice: HandshakeChoice::Kx,
        };
        let mut server_session = MessageBuilder::new(server_config, false).unwrap();

        // message A
        let msg_a = client_session.client_write_msg_a().unwrap();
        // client sends msg A to server
        server_session.server_read_msg_a(&msg_a).unwrap();
        let msg_b = server_session.server_write_msg_b().unwrap();
        server_session = server_session.into_transport_mode().unwrap();
        // server responds to client with msg B
        client_session.client_read_msg_b(&msg_b).unwrap();
        client_session = client_session.into_transport_mode().unwrap();

        // test client sending encrypted message to server and decrypting.
        let plaintext = "Hello".as_bytes();
        let ciphertext = client_session.encrypt_message(&plaintext).unwrap();
        // client sends ciphertext to server...
        let ct_len = server_session
            .decrypt_message_header(&ciphertext[..NOISE_MESSAGE_HEADER_SIZE])
            .unwrap() as usize;
        assert_eq!(ct_len, MAC_SIZE + plaintext.len());
        let decrypted_message = server_session
            .decrypt_message(&ciphertext[NOISE_MESSAGE_HEADER_SIZE..])
            .unwrap();
        assert_eq!(decrypted_message, plaintext);
    }
}
