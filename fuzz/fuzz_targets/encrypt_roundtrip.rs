#![no_main]
use libfuzzer_sys::fuzz_target;
use revault_net::noise::*;

const INIT_PRIVKEY: NoisePrivKey = NoisePrivKey([
    16, 85, 69, 127, 155, 247, 36, 200, 184, 156, 230, 255, 16, 125, 113, 4, 95, 78, 76, 188, 58,
    21, 55, 146, 195, 160, 199, 82, 41, 109, 199, 81,
]);
const INIT_PUBKEY: NoisePubKey = NoisePubKey([
    10, 12, 215, 103, 252, 231, 156, 109, 147, 53, 1, 147, 42, 240, 233, 242, 164, 67, 0, 81, 86,
    180, 233, 168, 75, 29, 216, 242, 15, 186, 225, 102,
]);

const RESP_PRIVKEY: NoisePrivKey = NoisePrivKey([
    96, 240, 118, 161, 68, 25, 19, 15, 12, 238, 118, 69, 95, 52, 3, 130, 2, 107, 15, 25, 135, 234,
    72, 36, 67, 124, 36, 228, 203, 101, 122, 110,
]);
const RESP_PUBKEY: NoisePubKey = NoisePubKey([
    19, 103, 106, 15, 169, 190, 254, 15, 187, 105, 61, 163, 152, 251, 238, 139, 253, 160, 165, 89,
    108, 67, 194, 161, 42, 72, 15, 38, 109, 193, 45, 125,
]);

fn kx_channels() -> (KXChannel, KXChannel) {
    let (init_1, msg_1) = KXHandshakeActOne::initiator(&INIT_PRIVKEY).unwrap();
    let resp_1 = KXHandshakeActOne::responder(&RESP_PRIVKEY, &INIT_PUBKEY, &msg_1).unwrap();

    let (resp_2, msg_2) = KXHandshakeActTwo::responder(resp_1).unwrap();
    let server_channel = KXChannel::from_handshake(resp_2).unwrap();

    let init_2 = KXHandshakeActTwo::initiator(init_1, &msg_2).unwrap();
    let client_channel = KXChannel::from_handshake(init_2).unwrap();

    (server_channel, client_channel)
}

fn kx_roundtrip(client_channel: &mut KXChannel, server_channel: &mut KXChannel, data: &[u8]) {
    let cypher = encrypt_message(client_channel, &data).unwrap();
    let plaintext = decrypt_message(server_channel, &cypher).unwrap();
    assert_eq!(&plaintext, data);

    let cypher = encrypt_message(server_channel, &data).unwrap();
    let plaintext = decrypt_message(client_channel, &cypher).unwrap();
    assert_eq!(&plaintext, data);
}

fn kk_channels() -> (KKChannel, KKChannel) {
    let (init_1, msg_1) = KKHandshakeActOne::initiator(&INIT_PRIVKEY, &RESP_PUBKEY).unwrap();
    let resp_1 = KKHandshakeActOne::responder(&RESP_PRIVKEY, &INIT_PUBKEY, &msg_1).unwrap();

    let (resp_2, msg_2) = KKHandshakeActTwo::responder(resp_1).unwrap();
    let server_channel = KKChannel::from_handshake(resp_2).unwrap();

    let init_2 = KKHandshakeActTwo::initiator(init_1, &msg_2).unwrap();
    let client_channel = KKChannel::from_handshake(init_2).unwrap();

    (server_channel, client_channel)
}

fn kk_roundtrip(client_channel: &mut KKChannel, server_channel: &mut KKChannel, data: &[u8]) {
    let cypher = encrypt_message(client_channel, &data).unwrap();
    decrypt_message(server_channel, &cypher).unwrap();

    let cypher = encrypt_message(server_channel, &data).unwrap();
    decrypt_message(client_channel, &cypher).unwrap();
}

fuzz_target!(|data: &[u8]| {
    let (mut kx_client, mut kx_server) = kx_channels();
    let (mut kk_client, mut kk_server) = kk_channels();

    if data.len() < NOISE_MESSAGE_MAX_SIZE {
        kx_roundtrip(&mut kx_client, &mut kx_server, data);
        kk_roundtrip(&mut kk_client, &mut kk_server, data);

        // Don't unwrap: they are surely invalid. But be sure we don't crash while
        // handling them.
        #[allow(unused)]
        if data.len() > NOISE_MESSAGE_HEADER_SIZE {
            let data = NoiseEncryptedMessage(data.to_vec());
            decrypt_message(&mut kx_client, &data);
            decrypt_message(&mut kx_server, &data);
            decrypt_message(&mut kk_client, &data);
            decrypt_message(&mut kk_server, &data);
        }
    }
});
