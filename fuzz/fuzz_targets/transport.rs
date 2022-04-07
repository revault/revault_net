#![no_main]
use libfuzzer_sys::fuzz_target;
use revault_net::noise::{PublicKey, SecretKey};
use revault_net::transport::*;
use std::{net::TcpListener, thread};

const INIT_PRIVKEY: SecretKey = SecretKey([
    16, 85, 69, 127, 155, 247, 36, 200, 184, 156, 230, 255, 16, 125, 113, 4, 95, 78, 76, 188, 58,
    21, 55, 146, 195, 160, 199, 82, 41, 109, 199, 81,
]);
const INIT_PUBKEY: PublicKey = PublicKey([
    10, 12, 215, 103, 252, 231, 156, 109, 147, 53, 1, 147, 42, 240, 233, 242, 164, 67, 0, 81, 86,
    180, 233, 168, 75, 29, 216, 242, 15, 186, 225, 102,
]);

const RESP_PRIVKEY: SecretKey = SecretKey([
    96, 240, 118, 161, 68, 25, 19, 15, 12, 238, 118, 69, 95, 52, 3, 130, 2, 107, 15, 25, 135, 234,
    72, 36, 67, 124, 36, 228, 203, 101, 122, 110,
]);
const RESP_PUBKEY: PublicKey = PublicKey([
    19, 103, 106, 15, 169, 190, 254, 15, 187, 105, 61, 163, 152, 251, 238, 139, 253, 160, 165, 89,
    108, 67, 194, 161, 42, 72, 15, 38, 109, 193, 45, 125,
]);

fn kk_client_server(data: &[u8]) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let msg_sent = data.to_vec();

    thread::spawn(move || {
        let mut cli_channel = KKTransport::connect(addr, &INIT_PRIVKEY, &RESP_PUBKEY)
            .expect("Client channel connecting");
        cli_channel
            .pubwrite(&msg_sent)
            .expect("Sending test message");
    });

    let (connection, _) = listener.accept().unwrap();
    let mut serv_transport =
        KKTransport::accept(connection, &RESP_PRIVKEY, &[INIT_PUBKEY]).unwrap();
    if let Ok(msg) = serv_transport.pubread() {
        assert_eq!(msg, data);
    }
}

fuzz_target!(|data: &[u8]| {
    kk_client_server(data);
});
