//! TCP wrapper API
//!
//! This module is a wrapper for TCP functionality that uses noise API internally
//! to automagically provide encrypted and authenticated channels.
//!

#[cfg(feature = "tor")]
use crate::tor::TorProxy;
use crate::{
    error::Error,
    message,
    noise::{
        KKChannel, KKHandshakeActOne, KKHandshakeActTwo, KKMessageActOne, KKMessageActTwo,
        NoiseEncryptedHeader, NoiseEncryptedMessage, PublicKey, SecretKey, KK_MSG_1_SIZE,
        KK_MSG_2_SIZE, NOISE_MESSAGE_HEADER_SIZE,
    },
};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

/// Wrapper type for a TcpStream and KKChannel that automatically enforces authenticated and
/// encrypted channels when communicating
#[derive(Debug)]
pub struct KKTransport {
    stream: TcpStream,
    channel: KKChannel,
}

impl KKTransport {
    /// Connect to server at given address, and enact Noise handshake with given private key.
    /// Sets a read timeout of 20 seconds.
    pub fn connect(
        addr: SocketAddr,
        my_noise_privkey: &SecretKey,
        their_noise_pubkey: &PublicKey,
    ) -> Result<KKTransport, Error> {
        let timeout = Duration::from_secs(20);
        let mut stream = TcpStream::connect_timeout(&addr, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        let channel = KKTransport::perform_client_handshake(
            &mut stream,
            my_noise_privkey,
            their_noise_pubkey,
        )?;
        Ok(KKTransport { stream, channel })
    }

    #[cfg(feature = "tor")]
    /// Connect to server at given tor address using the provided SOCKS5 proxy,
    /// and enact Noise handshake with given private key.
    /// Sets a read timeout of 20 seconds.
    pub fn tor_connect(
        addr: &str,
        proxy: &TorProxy,
        my_noise_privkey: &SecretKey,
        their_noise_pubkey: &PublicKey,
    ) -> Result<KKTransport, Error> {
        let mut stream =
            socks::Socks5Stream::connect(&format!("{}:{}", proxy.host, proxy.socks_port), addr)?
                .into_inner();
        let timeout = Duration::from_secs(20);
        stream.set_read_timeout(Some(timeout))?;
        let channel = KKTransport::perform_client_handshake(
            &mut stream,
            my_noise_privkey,
            their_noise_pubkey,
        )?;
        Ok(KKTransport { stream, channel })
    }

    // Used by connect() and tor_connect() to perform the handshake
    fn perform_client_handshake(
        stream: &mut TcpStream,
        my_noise_privkey: &SecretKey,
        their_noise_pubkey: &PublicKey,
    ) -> Result<KKChannel, Error> {
        let (cli_act_1, msg_1) =
            KKHandshakeActOne::initiator(my_noise_privkey, their_noise_pubkey)?;

        // write msg_1 to stream (e, es, ss)
        stream.write_all(&msg_1.0)?;

        // read msg_2 from stream (e, ee, se)
        let mut msg_2 = [0u8; KK_MSG_2_SIZE];
        stream.read_exact(&mut msg_2)?;

        let msg_act_2 = KKMessageActTwo(msg_2);
        let cli_act_2 = KKHandshakeActTwo::initiator(cli_act_1, &msg_act_2)?;
        KKChannel::from_handshake(cli_act_2).map_err(|e| e.into())
    }

    /// Accept an incoming connection and immediately perform the noise KK handshake
    /// as a responder with our single private key and a set of possible public key for them.
    /// This is used by servers to identify the origin of the message.
    pub fn accept(
        listener: &TcpListener,
        my_noise_privkey: &SecretKey,
        their_possible_pubkeys: &[PublicKey],
    ) -> Result<KKTransport, Error> {
        let (mut stream, _) = listener.accept().map_err(|e| Error::Transport(e))?;

        // read msg_1 from stream
        let mut msg_1 = [0u8; KK_MSG_1_SIZE];
        stream.read_exact(&mut msg_1)?;
        let msg_act_1 = KKMessageActOne(msg_1);

        let serv_act_1 =
            KKHandshakeActOne::responder(&my_noise_privkey, their_possible_pubkeys, &msg_act_1)?;
        let (serv_act_2, msg_2) = KKHandshakeActTwo::responder(serv_act_1)?;
        let channel = KKChannel::from_handshake(serv_act_2)?;

        // write msg_2 to stream
        stream.write_all(&msg_2.0)?;

        Ok(KKTransport { stream, channel })
    }

    // Read an encrypted Noise message from the communication channel
    fn read(&mut self) -> Result<Vec<u8>, Error> {
        let mut cypherheader = [0u8; NOISE_MESSAGE_HEADER_SIZE];
        self.stream.read_exact(&mut cypherheader)?;
        let msg_len = self
            .channel
            .decrypt_header(&NoiseEncryptedHeader(cypherheader))?;

        // Note that `msg_len` cannot be > 65K (2 bytes)
        let mut cypherbody = vec![0u8; msg_len as usize];
        self.stream.read_exact(&mut cypherbody)?;
        self.channel
            .decrypt_message(&NoiseEncryptedMessage(cypherbody))
            .map_err(|e| e.into())
    }

    #[cfg(feature = "fuzz")]
    #[allow(missing_docs)]
    pub fn pubread(&mut self) -> Result<Vec<u8>, Error> {
        self.read()
    }

    // Encrypt and write a message to the communication channel
    fn write(&mut self, msg: &[u8]) -> Result<(), Error> {
        let encrypted_msg = self.channel.encrypt_message(msg)?.0;
        self.stream.write_all(&encrypted_msg).map_err(|e| e.into())
    }

    #[cfg(feature = "fuzz")]
    #[allow(missing_docs)]
    pub fn pubwrite(&mut self, msg: &[u8]) -> Result<(), Error> {
        self.write(msg)
    }

    /// Send a request to the other end of the encrypted channel, and return their response.
    pub fn send_req<T>(&mut self, req: &message::Request) -> Result<T, Error>
    where
        T: serde::de::DeserializeOwned,
    {
        let raw_req = serde_json::to_vec(&req)?;
        log::trace!("Sending request: '{}'", String::from_utf8_lossy(&raw_req));
        self.write(&raw_req)?;

        loop {
            let raw_resp = self.read()?;
            log::trace!("Read response: '{}'", String::from_utf8_lossy(&raw_resp));
            let resp: message::Response<T> = serde_json::from_slice(&raw_resp)?;
            if resp.id == req.id() {
                return Ok(resp.result);
            } else {
                log::trace!("Reponse was not for us. Continuing to read.");
            }
        }
    }

    // DRY helper to write a response to the communication channel
    fn _write_resp<T: serde::ser::Serialize>(
        &mut self,
        resp: &message::Response<T>,
    ) -> Result<(), Error> {
        let raw_resp = serde_json::to_vec(&resp)?;
        log::trace!("Sending response: '{}'", String::from_utf8_lossy(&raw_resp));
        self.write(&raw_resp)
    }

    /// Read a request from the other end of the encrypted channel.
    pub fn read_req<F>(&mut self, response_cb: F) -> Result<(), Error>
    where
        F: FnOnce(message::RequestParams) -> Option<message::ResponseResult>,
    {
        let raw_req = self.read()?;
        log::trace!("Read request: '{}'", String::from_utf8_lossy(&raw_req));
        let req: message::Request = serde_json::from_slice(&raw_req)?;

        let id = req.id();
        if let Some(result) = response_cb(req.params()) {
            self._write_resp(&message::Response { result, id })?;
        }

        Ok(())
    }

    /// This is the async version of [read_req]
    pub async fn read_req_async<F, Fut>(&mut self, response_cb: F) -> Result<(), Error>
    where
        F: FnOnce(message::RequestParams) -> Fut,
        Fut: std::future::Future<Output = Option<message::ResponseResult>>,
    {
        let raw_req = self.read()?;
        log::trace!("Read request: '{}'", String::from_utf8_lossy(&raw_req));
        let req: message::Request = serde_json::from_slice(&raw_req)?;

        let id = req.id();
        if let Some(result) = response_cb(req.params()).await {
            self._write_resp(&message::Response { result, id })?;
        }

        Ok(())
    }

    /// Get the static public key of the peer
    pub fn remote_static(&self) -> PublicKey {
        self.channel.remote_static()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::gen_keypair;
    use std::{collections::BTreeMap, fs, process::Command, str::FromStr, thread};

    #[test]
    #[cfg(feature = "tor")]
    fn test_transport_kk_tor() {
        let ((client_pubkey, client_privkey), (server_pubkey, server_privkey)) =
            (gen_keypair(), gen_keypair());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let server_addr = listener.local_addr().unwrap();

        let datadir = "scratch_test_datadir";
        // Clean from previous run
        fs::remove_dir_all(&datadir).unwrap_or_else(|_| ());
        fs::create_dir(&datadir).unwrap();
        let mut file = fs::File::create(format!("{}/torrc", datadir)).unwrap();
        let torrc = format!(
            r#"HiddenServiceDir {0}/hidden_service/
HiddenServicePort 19051 127.0.0.1:{1}
DataDirectory {0}/server
Log notice file {0}/server/log
SOCKSPort 0"#,
            datadir,
            server_addr.port(),
        );
        file.write_all(torrc.as_bytes()).unwrap();
        let mut hidden_service_process = Command::new("tor")
            .args(&["-f", &format!("{}/torrc", datadir)])
            .spawn()
            .expect("Tor failed to start");

        let msg = "Test message".as_bytes();

        // hidden_service_process won't be killed if we panic here, so
        // instead of unwrapping directly I'm using `?` in a closure
        // and unwrapping the result after killing tor.
        // This way if there's an error we don't leave dangling tors around
        let c = || -> Result<_, Box<dyn std::error::Error>> {
            let client_proxy = TorProxy::start_tor(format!("{}/client/", datadir).into(), None);

            // server thread
            let server_thread = thread::spawn(move || {
                let my_noise_privkey = server_privkey;
                let their_noise_pubkey = client_pubkey;
                let mut server_transport =
                    KKTransport::accept(&listener, &my_noise_privkey, &[their_noise_pubkey])?;
                server_transport.read()
            });

            // Giving tor a bit of time to start...
            std::thread::sleep(std::time::Duration::from_secs(30));
            let hidden_service_onion =
                fs::read_to_string(format!("{}/hidden_service/hostname", datadir))?;
            let hidden_service_address = format!("{}:19051", hidden_service_onion.trim_end());

            // client thread
            let mut cli_channel = KKTransport::tor_connect(
                &hidden_service_address,
                &client_proxy,
                &client_privkey,
                &server_pubkey,
            )?;
            cli_channel.write(&msg)?;

            Ok(server_thread
                .join()
                .map_err(|_| String::from("Error joining thread"))??)
        };

        let received_msg = c();
        hidden_service_process.kill().unwrap_or_else(|_| {});
        assert_eq!(msg, received_msg.unwrap().as_slice());
    }

    #[test]
    fn test_transport_kk() {
        let ((client_pubkey, client_privkey), (server_pubkey, server_privkey)) =
            (gen_keypair(), gen_keypair());

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        // client thread
        let cli_thread = thread::spawn(move || {
            let my_noise_privkey = client_privkey;
            let their_noise_pubkey = server_pubkey;

            let mut cli_channel =
                KKTransport::connect(addr, &my_noise_privkey, &their_noise_pubkey)
                    .expect("Client channel connecting");
            let msg = "Test message".as_bytes();
            cli_channel.write(&msg).expect("Sending test message");
            msg
        });

        let mut server_transport =
            KKTransport::accept(&listener, &server_privkey, &[client_pubkey])
                .expect("Server channel binding and accepting");

        let sent_msg = cli_thread.join().unwrap();
        let received_msg = server_transport.read().unwrap();
        assert_eq!(sent_msg.to_vec(), received_msg);
    }

    // Send a get_sigs from a client and get back a sigs
    #[test]
    fn rw_sanity_check() {
        let ((client_pubkey, client_privkey), (server_pubkey, server_privkey)) =
            (gen_keypair(), gen_keypair());

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let id = bitcoin::Txid::from_str(
            "0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap();
        let req = message::coordinator::GetSigs { id };
        let params_str =
            r#"{"id":"0000000000000000000000000000000000000000000000000000000000000000"}"#;

        let mut signatures = BTreeMap::new();
        let pubkey = bitcoin::PublicKey::from_str(
            "035be5e9478209674a96e60f1f037f6176540fd001fa1d64694770c56a7709c42c",
        )
        .unwrap();
        let sig = bitcoin::secp256k1::Signature::from_str("3045022100dc4dc264a9fef17a3f253449cf8c397ab6f16fb3d63d86940b5586823dfd02ae02203b461bb4336b5ecbaefd6627aa922efc048fec0c881c10c4c9428fca69c132a2").unwrap();
        signatures.insert(pubkey.key, sig);
        let resp = message::coordinator::Sigs { signatures };
        // Note how it does not contain 'result'
        let resp_str = r#"{"signatures":{"035be5e9478209674a96e60f1f037f6176540fd001fa1d64694770c56a7709c42c":"3045022100dc4dc264a9fef17a3f253449cf8c397ab6f16fb3d63d86940b5586823dfd02ae02203b461bb4336b5ecbaefd6627aa922efc048fec0c881c10c4c9428fca69c132a2"}}"#;

        let cli_thread = thread::spawn(move || {
            let my_noise_privkey = client_privkey;
            let their_noise_pubkey = server_pubkey;

            let mut cli_channel =
                KKTransport::connect(addr, &my_noise_privkey, &their_noise_pubkey)
                    .expect("Client channel connecting");
            let resp: message::coordinator::Sigs =
                cli_channel.send_req(&req.into()).expect("Sending get_sigs");
            assert_eq!(serde_json::to_string(&resp).unwrap(), resp_str.to_string());
        });

        let mut server_transport =
            KKTransport::accept(&listener, &server_privkey, &[client_pubkey])
                .expect("Server channel binding and accepting");
        server_transport
            .read_req(|params| {
                assert_eq!(
                    serde_json::to_string(&params).unwrap(),
                    params_str.to_string()
                );
                Some(message::ResponseResult::Sigs(resp))
            })
            .expect("Reading request");

        cli_thread.join().unwrap();
    }
}
