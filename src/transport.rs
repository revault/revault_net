//! TCP wrapper API
//!
//! This module is a wrapper for TCP functionality that uses noise API internally
//! to automagically provide encrypted and authenticated channels.
//!

use crate::{
    error::Error,
    noise::{
        KKChannel, KKHandshakeActOne, KKHandshakeActTwo, KKMessageActOne, KKMessageActTwo,
        NoiseEncryptedMessage, NoisePrivKey, NoisePubKey, KK_MSG_1_SIZE, KK_MSG_2_SIZE,
        NOISE_MESSAGE_MAX_SIZE,
    },
};
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};

/// Wrapper type for a TcpStream and KKChannel that automatically enforces authenticated and
/// encrypted channels when communicating
#[derive(Debug)]
pub struct KKTransport {
    stream: TcpStream,
    channel: KKChannel,
}

impl KKTransport {
    /// Connect to server at given address, and enact Noise handshake with given private key.
    pub fn connect<A: ToSocketAddrs>(
        addr: A,
        my_noise_privkey: NoisePrivKey,
        their_noise_pubkey: NoisePubKey,
    ) -> Result<KKTransport, Error> {
        let mut stream = TcpStream::connect(addr)
            .map_err(|e| Error::Transport(format!("TCP connection failed: {:?}", e)))?;

        let (cli_act_1, msg_1) =
            KKHandshakeActOne::initiator(&my_noise_privkey, &their_noise_pubkey)
                .map_err(|e| Error::Noise(format!("Failed to initiate act 1: {:?}", e)))?;

        // write msg_1 to stream (e, es, ss)
        stream.write_all(&msg_1.0).map_err(|e| {
            Error::Transport(format!("Failed to write message 1 to TcpStream: {:?}", e))
        })?;

        // read msg_2 from stream (e, ee, se)
        let mut msg_2 = [0u8; KK_MSG_2_SIZE];
        stream.read_exact(&mut msg_2).map_err(|e| {
            Error::Transport(format!("Failed to read message 2 from TcpStream: {:?}", e))
        })?;

        let msg_act_2 = KKMessageActTwo(msg_2);
        let cli_act_2 = KKHandshakeActTwo::initiator(cli_act_1, &msg_act_2)
            .map_err(|e| Error::Noise(format!("Failed to initiate act 2: {:?}", e)))?;
        let channel = KKChannel::from_handshake(cli_act_2)
            .map_err(|e| Error::Noise(format!("Failed to construct KKChannel: {:?}", e)))?;

        Ok(KKTransport { stream, channel })
    }

    /// Accept an incoming connection and immediately perform the noise KK handshake
    /// as a responder with our single private key and a set of possible public key for them.
    /// This is used by servers to identify the origin of the message.
    pub fn accept(
        listener: TcpListener,
        my_noise_privkey: NoisePrivKey,
        their_possible_pubkeys: &[NoisePubKey],
    ) -> Result<KKTransport, Error> {
        let (mut stream, _) = listener
            .accept()
            .map_err(|e| Error::Transport(format!("TCP accept failed: {:?}", e)))?;

        // read msg_1 from stream
        let mut msg_1 = [0u8; KK_MSG_1_SIZE];
        stream.read_exact(&mut msg_1).map_err(|e| {
            Error::Transport(format!("Failed to read message 1 from TcpStream: {:?}", e))
        })?;
        let msg_act_1 = KKMessageActOne(msg_1);

        let serv_act_1 =
            KKHandshakeActOne::responder(&my_noise_privkey, their_possible_pubkeys, &msg_act_1)
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

    /// Write a message to the other end of the encrypted communication channel.
    pub fn write(&mut self, msg: &[u8]) -> Result<(), Error> {
        let encrypted_msg = self.channel.encrypt_message(msg)?.0;
        self.stream.write_all(&encrypted_msg).map_err(|e| {
            Error::Transport(format!(
                "Failed to send encrypted message with TcpStream: {:?}",
                e
            ))
        })
    }

    /// Read a message from the other end of the encrypted communication channel.
    pub fn read(&mut self) -> Result<Vec<u8>, Error> {
        let mut encrypted_msg = vec![0u8; NOISE_MESSAGE_MAX_SIZE];
        let mut bytes_read = 0;

        // Note that read_to_end() will read thousands of bytes for whatever reason
        // so we emulate it here.
        loop {
            match self.stream.read(&mut encrypted_msg) {
                Ok(0) => break,
                Ok(n) => bytes_read += n,
                Err(e) => match e.kind() {
                    // Fine, we may have gotten the message anyways. They just aren't polite
                    io::ErrorKind::WouldBlock
                    | io::ErrorKind::Interrupted
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::BrokenPipe => break,
                    // That's actually bad
                    _ => return Err(Error::Transport(format!("Reading from stream: '{}'", e))),
                },
            };
        }
        encrypted_msg.truncate(bytes_read);

        let encrypted_msg = NoiseEncryptedMessage(encrypted_msg);
        self.channel.decrypt_message(&encrypted_msg)
    }

    /// Get the static public key of the peer
    pub fn remote_static(&self) -> NoisePubKey {
        self.channel.remote_static()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;
    use snow::{resolvers::SodiumResolver, Builder, Keypair};
    use std::convert::TryInto;
    use std::thread;

    /// Revault must specify the SodiumResolver to use sodiumoxide as the cryptography provider
    /// when generating a static key pair for secure communication.
    pub fn generate_keypair() -> Keypair {
        let noise_params = "Noise_KK_25519_ChaChaPoly_SHA256"
            .parse()
            .map_err(|e| Error::Noise(format!("Invalid Noise Pattern: {}", e)))
            .unwrap();
        Builder::with_resolver(noise_params, Box::new(SodiumResolver::default()))
            .generate_keypair()
            .unwrap()
    }

    #[test]
    fn test_transport_kk() {
        let (client_keypair, server_keypair) = (generate_keypair(), generate_keypair());

        let client_pubkey = NoisePubKey(client_keypair.public[..].try_into().unwrap());
        let server_pubkey = NoisePubKey(server_keypair.public[..].try_into().unwrap());
        let server_privkey = NoisePrivKey(server_keypair.private[..].try_into().unwrap());

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        // client thread
        let cli_thread = thread::spawn(move || {
            let my_noise_privkey = NoisePrivKey(client_keypair.private[..].try_into().unwrap());
            let their_noise_pubkey = server_pubkey;

            let mut cli_channel = KKTransport::connect(addr, my_noise_privkey, their_noise_pubkey)
                .expect("Client channel connecting");
            let msg = "Test message".as_bytes();
            cli_channel.write(&msg).expect("Sending test message");
            msg
        });

        let mut server_transport = KKTransport::accept(listener, server_privkey, &[client_pubkey])
            .expect("Server channel binding and accepting");

        let sent_msg = cli_thread.join().unwrap();
        let received_msg = server_transport.read().unwrap();
        assert_eq!(sent_msg.to_vec(), received_msg);
    }
}
