//! TCP wrapper API
//!
//! This module is a wrapper for TCP functionality that uses noise API internally
//! to automagically provide encrypted and authenticated channels.
//!

use crate::{
    error::Error,
    noise::{
        decrypt_message, encrypt_message, KKChannel, KKHandshakeActOne, KKHandshakeActTwo,
        KKMessageActOne, KKMessageActTwo, KXChannel, KXHandshakeActOne, KXHandshakeActTwo,
        KXMessageActOne, KXMessageActTwo, NoiseEncryptedMessage, NoisePrivKey, NoisePubKey,
        KK_MSG_1_SIZE, KK_MSG_2_SIZE, KX_MSG_1_SIZE, KX_MSG_2_SIZE, NOISE_MESSAGE_MAX_SIZE,
    },
};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};

// FIXME: implement constructor for ChannelInputs that reads from config file
// and priv_key storage. Make my_noise_privkey field private.
/// Authenticated and encrypted channels are set up with each TCP connection,
/// thus requiring the local static private key and optionally the remote
/// public key as inputs.
pub struct ChannelInputs {
    /// Local static private key
    pub my_noise_privkey: NoisePrivKey,
    /// Remote static public key
    pub their_noise_pubkey: Option<NoisePubKey>,
}

/// The Transport trait defines the general API for communication between a Revault server and client
pub trait Transport {
    /// Called by Revault client; connect to server at given address, and enact Noise handshake
    /// with given channel inputs.
    fn connect<A: ToSocketAddrs>(addr: A, channel_inputs: ChannelInputs) -> Result<Self, Error>
    where
        Self: std::marker::Sized;
    /// Called by Revault server; listen for connections on given address, and enact Noise handshake
    /// with given channel inputs.
    fn bind_accept<A: ToSocketAddrs>(addr: A, channel_inputs: ChannelInputs) -> Result<Self, Error>
    where
        Self: std::marker::Sized;
    /// Send message using the TcpStream and NoiseChannel that has been constructed either with
    /// connect() or bind_accept()
    fn send_msg(&mut self, msg: &[u8]) -> Result<(), Error>;
    /// Receive message using the TcpStream and NoiseChannel that has been constructed either with
    /// connect() or bind_accept()
    fn receive_msg(&mut self) -> Result<Vec<u8>, Error>;
}

/// Wrapper type for a TcpStream and KXChannel that automatically enforces authenticated and
/// encrypted channels when communicating
#[derive(Debug)]
pub struct KXTransport {
    stream: TcpStream,
    channel: KXChannel,
}

impl Transport for KXTransport {
    fn connect<A: ToSocketAddrs>(
        addr: A,
        channel_inputs: ChannelInputs,
    ) -> Result<KXTransport, Error> {
        let mut stream = TcpStream::connect(addr)
            .map_err(|e| Error::Transport(format!("TCP connection failed: {:?}", e)))?;

        let (cli_act_1, msg_1) = KXHandshakeActOne::initiator(&channel_inputs.my_noise_privkey)
            .map_err(|e| Error::Noise(format!("Failed to initiate act 1: {:?}", e)))?;

        // write msg_1 to stream (e)
        stream.write_all(&msg_1.0).map_err(|e| {
            Error::Transport(format!("Failed to write message 1 to TcpStream: {:?}", e))
        })?;

        // read msg_2 from stream (e, ee, se, s, es)
        let mut msg_2 = [0u8; KX_MSG_2_SIZE];
        let mut read = 0;
        while read < KX_MSG_2_SIZE {
            read += stream.read(&mut msg_2).map_err(|e| {
                Error::Transport(format!("Failed to read message 2 from TcpStream: {:?}", e))
            })?;
        }

        let msg_act_2 = KXMessageActTwo(msg_2);
        let cli_act_2 = KXHandshakeActTwo::initiator(cli_act_1, &msg_act_2)
            .map_err(|e| Error::Noise(format!("Failed to initiate act 2: {:?}", e)))?;
        let channel = KXChannel::from_handshake(cli_act_2)
            .map_err(|e| Error::Noise(format!("Failed to construct KXChannel: {:?}", e)))?;

        Ok(KXTransport { stream, channel })
    }

    fn bind_accept<A: ToSocketAddrs>(
        addr: A,
        channel_inputs: ChannelInputs,
    ) -> Result<KXTransport, Error> {
        let listener = TcpListener::bind(addr)
            .map_err(|e| Error::Transport(format!("TCP binding failed: {:?}", e)))?;
        let (mut stream, _addr) = listener
            .accept()
            .map_err(|e| Error::Transport(format!("TCP accept failed: {:?}", e)))?;

        // read msg_1 from stream
        let mut msg_1 = [0u8; KX_MSG_1_SIZE];
        stream.read(&mut msg_1).map_err(|e| {
            Error::Transport(format!("Failed to read message 1 from TcpStream: {:?}", e))
        })?;
        let msg_act_1 = KXMessageActOne(msg_1);

        let serv_act_1 = KXHandshakeActOne::responder(
            &channel_inputs.my_noise_privkey,
            &channel_inputs.their_noise_pubkey.unwrap(),
            &msg_act_1,
        )
        .map_err(|e| Error::Noise(format!("Failed to respond in act 1: {:?}", e)))?;
        let (serv_act_2, msg_2) = KXHandshakeActTwo::responder(serv_act_1)
            .map_err(|e| Error::Noise(format!("Failed to respond in act 2: {:?}", e)))?;
        let channel = KXChannel::from_handshake(serv_act_2)
            .map_err(|e| Error::Noise(format!("Failed to construct KXChannel: {:?}", e)))?;

        // write msg_2 to stream
        stream.write_all(&msg_2.0).map_err(|e| {
            Error::Transport(format!("Failed to write message 2 to TcpStream: {:?}", e))
        })?;

        Ok(KXTransport { stream, channel })
    }

    fn send_msg(&mut self, msg: &[u8]) -> Result<(), Error> {
        // Encrypt a serialized msg using KXChannel
        let encrypted_msg = encrypt_message(&mut self.channel, msg)?.0;
        // Send encrypted msg through TcpStream
        self.stream.write_all(&encrypted_msg).map_err(|e| {
            Error::Transport(format!(
                "Failed to send encrypted message with TcpStream: {:?}",
                e
            ))
        })?;

        Ok(())
    }

    fn receive_msg(&mut self) -> Result<Vec<u8>, Error> {
        // Recieve encrypted msg from the TcpStream
        let mut encrypted_msg = vec![0u8; NOISE_MESSAGE_MAX_SIZE];

        self.stream.read(&mut encrypted_msg).map_err(|e| {
            Error::Transport(format!(
                "Failed to read encrypted message from TcpStream: {:?}",
                e
            ))
        })?;

        let encrypted_msg = NoiseEncryptedMessage(encrypted_msg);
        // Decrypt msg using KXChannel
        Ok(decrypt_message(&mut self.channel, &encrypted_msg)?)
    }
}

/// Wrapper type for a TcpStream and KKChannel that automatically enforces authenticated and
/// encrypted channels when communicating
#[derive(Debug)]
pub struct KKTransport {
    stream: TcpStream,
    channel: KKChannel,
}

impl Transport for KKTransport {
    fn connect<A: ToSocketAddrs>(
        addr: A,
        channel_inputs: ChannelInputs,
    ) -> Result<KKTransport, Error> {
        let mut stream = TcpStream::connect(addr)
            .map_err(|e| Error::Transport(format!("TCP connection failed: {:?}", e)))?;

        let (cli_act_1, msg_1) = KKHandshakeActOne::initiator(
            &channel_inputs.my_noise_privkey,
            &channel_inputs.their_noise_pubkey.unwrap(),
        )
        .map_err(|e| Error::Noise(format!("Failed to initiate act 1: {:?}", e)))?;

        // write msg_1 to stream (e, es, ss)
        stream.write_all(&msg_1.0).map_err(|e| {
            Error::Transport(format!("Failed to write message 1 to TcpStream: {:?}", e))
        })?;

        // read msg_2 from stream (e, ee, se)
        let mut msg_2 = [0u8; KK_MSG_2_SIZE];
        let mut read = 0;
        while read < KK_MSG_2_SIZE {
            read += stream.read(&mut msg_2).map_err(|e| {
                Error::Transport(format!("Failed to read message 2 from TcpStream: {:?}", e))
            })?;
        }

        let msg_act_2 = KKMessageActTwo(msg_2);
        let cli_act_2 = KKHandshakeActTwo::initiator(cli_act_1, &msg_act_2)
            .map_err(|e| Error::Noise(format!("Failed to initiate act 2: {:?}", e)))?;
        let channel = KKChannel::from_handshake(cli_act_2)
            .map_err(|e| Error::Noise(format!("Failed to construct KKChannel: {:?}", e)))?;

        Ok(KKTransport { stream, channel })
    }

    fn bind_accept<A: ToSocketAddrs>(
        addr: A,
        channel_inputs: ChannelInputs,
    ) -> Result<KKTransport, Error> {
        let listener = TcpListener::bind(addr)
            .map_err(|e| Error::Transport(format!("TCP binding failed: {:?}", e)))?;
        let (mut stream, _addr) = listener
            .accept()
            .map_err(|e| Error::Transport(format!("TCP accept failed: {:?}", e)))?;

        // read msg_1 from stream
        let mut msg_1 = [0u8; KK_MSG_1_SIZE];
        stream.read(&mut msg_1).map_err(|e| {
            Error::Transport(format!("Failed to read message 1 from TcpStream: {:?}", e))
        })?;
        let msg_act_1 = KKMessageActOne(msg_1);

        let serv_act_1 = KKHandshakeActOne::responder(
            &channel_inputs.my_noise_privkey,
            &channel_inputs.their_noise_pubkey.unwrap(),
            &msg_act_1,
        )
        .map_err(|e| Error::Noise(format!("Failed to respond in act 1: {:?}", e)))?;
        let (serv_act_2, msg_2) = KKHandshakeActTwo::responder(serv_act_1)
            .map_err(|e| Error::Noise(format!("Failed to respond in act 2: {:?}", e)))?;
        let channel = KKChannel::from_handshake(serv_act_2)
            .map_err(|e| Error::Noise(format!("Failed to construct KXChannel: {:?}", e)))?;

        // write msg_2 to stream
        stream.write_all(&msg_2.0).map_err(|e| {
            Error::Transport(format!("Failed to write message 2 to TcpStream: {:?}", e))
        })?;

        Ok(KKTransport { stream, channel })
    }

    fn send_msg(&mut self, msg: &[u8]) -> Result<(), Error> {
        // Encrypt a serialized msg using KKChannel
        let encrypted_msg = encrypt_message(&mut self.channel, msg)?.0;
        // Send encrypted msg through TcpStream
        self.stream.write_all(&encrypted_msg).map_err(|e| {
            Error::Transport(format!(
                "Failed to send encrypted message with TcpStream: {:?}",
                e
            ))
        })?;

        Ok(())
    }

    fn receive_msg(&mut self) -> Result<Vec<u8>, Error> {
        // Recieve encrypted msg from the TcpStream
        let mut encrypted_msg = vec![0u8; NOISE_MESSAGE_MAX_SIZE];
        self.stream.read(&mut encrypted_msg).map_err(|e| {
            Error::Transport(format!(
                "Failed to read encrypted message from TcpStream: {:?}",
                e
            ))
        })?;
        let encrypted_msg = NoiseEncryptedMessage(encrypted_msg);
        // Decrypt msg using KKChannel
        Ok(decrypt_message(&mut self.channel, &encrypted_msg)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;
    use snow::{params::NoiseParams, resolvers::SodiumResolver, Builder, Keypair};
    use std::thread;
    use std::{convert::TryInto, time::Duration};

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
    fn test_transport_kx() {
        // client init
        let cli_handshake_choice = HandshakeChoice::Kx;
        let cli_noise_params = get_noise_params(&cli_handshake_choice).unwrap();
        let client_keypair = generate_keypair(cli_noise_params.clone());

        //server init
        let serv_handshake_choice = HandshakeChoice::Kx;
        let serv_noise_params = get_noise_params(&serv_handshake_choice).unwrap();
        let server_keypair = generate_keypair(serv_noise_params.clone());
        let client_pubkey = NoisePubKey(client_keypair.public[..].try_into().unwrap());

        let addrs = "127.0.0.1:8000";

        // server thread
        let serv_thread = thread::spawn(move || {
            let my_noise_privkey = NoisePrivKey(server_keypair.private[..].try_into().unwrap());
            let their_noise_pubkey = Some(client_pubkey);
            let serv_channel_inputs = ChannelInputs {
                my_noise_privkey,
                their_noise_pubkey,
            };

            let mut server_channel = KXTransport::bind_accept(addrs.clone(), serv_channel_inputs)
                .expect("Server channel binding and accepting");
            thread::sleep(Duration::from_millis(10));
            server_channel.receive_msg().unwrap()
        });

        // client thread
        let cli_thread = thread::spawn(move || {
            let my_noise_privkey = NoisePrivKey(client_keypair.private[..].try_into().unwrap());
            let their_noise_pubkey = None;
            let cli_channel_inputs = ChannelInputs {
                my_noise_privkey,
                their_noise_pubkey,
            };

            let mut cli_channel = KXTransport::connect(addrs.clone(), cli_channel_inputs)
                .expect("Client channel connecting");
            let msg = "Test message".as_bytes();
            cli_channel.send_msg(&msg).expect("Sending test message");
            msg
        });

        let received_msg = serv_thread.join().unwrap();
        let sent_msg = cli_thread.join().unwrap();
        assert_eq!(sent_msg.to_vec(), received_msg);
    }

    #[test]
    fn test_transport_kk() {
        // client init part 1
        let cli_handshake_choice = HandshakeChoice::Kk;
        let cli_noise_params = get_noise_params(&cli_handshake_choice).unwrap();
        let client_keypair = generate_keypair(cli_noise_params.clone());

        //server init
        let serv_handshake_choice = HandshakeChoice::Kk;
        let serv_noise_params = get_noise_params(&serv_handshake_choice).unwrap();
        let server_keypair = generate_keypair(serv_noise_params.clone());
        let client_pubkey = NoisePubKey(client_keypair.public[..].try_into().unwrap());

        // client init part 2
        let server_pubkey = NoisePubKey(server_keypair.public[..].try_into().unwrap());

        let addrs = "127.0.0.1:8001";

        // server thread
        let serv_thread = thread::spawn(move || {
            let my_noise_privkey = NoisePrivKey(server_keypair.private[..].try_into().unwrap());
            let their_noise_pubkey = Some(client_pubkey);
            let serv_channel_inputs = ChannelInputs {
                my_noise_privkey,
                their_noise_pubkey,
            };

            let mut server_channel = KKTransport::bind_accept(addrs.clone(), serv_channel_inputs)
                .expect("Server channel binding and accepting");
            thread::sleep(Duration::from_millis(10));
            server_channel.receive_msg().unwrap()
        });

        // client thread
        let cli_thread = thread::spawn(move || {
            let my_noise_privkey = NoisePrivKey(client_keypair.private[..].try_into().unwrap());
            let their_noise_pubkey = Some(server_pubkey);
            let cli_channel_inputs = ChannelInputs {
                my_noise_privkey,
                their_noise_pubkey,
            };

            let mut cli_channel = KKTransport::connect(addrs.clone(), cli_channel_inputs)
                .expect("Client channel connecting");
            let msg = "Test message".as_bytes();
            cli_channel.send_msg(&msg).expect("Sending test message");
            msg
        });

        let received_msg = serv_thread.join().unwrap();
        let sent_msg = cli_thread.join().unwrap();
        assert_eq!(sent_msg.to_vec(), received_msg);
    }
}
