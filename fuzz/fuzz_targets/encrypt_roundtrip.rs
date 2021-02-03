#![no_main]
use libfuzzer_sys::fuzz_target;
use revault_net::noise::*;
use std::convert::TryInto;

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

fn kk_channels() -> (KKChannel, KKChannel) {
    let (init_1, msg_1) = KKHandshakeActOne::initiator(&INIT_PRIVKEY, &RESP_PUBKEY).unwrap();
    let resp_1 = KKHandshakeActOne::responder(&RESP_PRIVKEY, &[INIT_PUBKEY], &msg_1).unwrap();

    let (resp_2, msg_2) = KKHandshakeActTwo::responder(resp_1).unwrap();
    let server_channel = KKChannel::from_handshake(resp_2).unwrap();

    let init_2 = KKHandshakeActTwo::initiator(init_1, &msg_2).unwrap();
    let client_channel = KKChannel::from_handshake(init_2).unwrap();

    (server_channel, client_channel)
}

fn kk_roundtrip(client_channel: &mut KKChannel, server_channel: &mut KKChannel, data: &[u8]) {
    // Client --> Server
    let cypher = client_channel.encrypt_message(data).unwrap();
    let header = NoiseEncryptedHeader(cypher.0[..NOISE_MESSAGE_HEADER_SIZE].try_into().unwrap());
    let body = NoiseEncryptedMessage(cypher.0[NOISE_MESSAGE_HEADER_SIZE..].to_vec());

    let length = server_channel.decrypt_header(&header).unwrap();
    assert_eq!(body.0.len(), length as usize);
    let plaintext = server_channel.decrypt_message(&body).unwrap();
    assert_eq!(&plaintext, data);

    // Server --> Client
    let cypher = server_channel.encrypt_message(data).unwrap();
    let header = NoiseEncryptedHeader(cypher.0[..NOISE_MESSAGE_HEADER_SIZE].try_into().unwrap());
    let body = NoiseEncryptedMessage(cypher.0[NOISE_MESSAGE_HEADER_SIZE..].to_vec());

    let length = client_channel.decrypt_header(&header).unwrap();
    assert_eq!(body.0.len(), length as usize);
    let plaintext = client_channel.decrypt_message(&body).unwrap();
    assert_eq!(&plaintext, data);
}

fuzz_target!(|data: &[u8]| {
    let (mut kk_client, mut kk_server) = kk_channels();

    // Encrypt `data` then decrypt it
    kk_roundtrip(&mut kk_client, &mut kk_server, data);

    // The opposite: treat `data` as encrypted data
    if data.len() < NOISE_MESSAGE_MAX_SIZE {
        // Don't unwrap: they are surely invalid. But be sure we don't crash while
        // handling them.
        #[allow(unused)]
        if data.len() > NOISE_MESSAGE_HEADER_SIZE {
            let header =
                NoiseEncryptedHeader(data[..NOISE_MESSAGE_HEADER_SIZE].try_into().unwrap());
            kk_client.decrypt_header(&header);
            kk_server.decrypt_header(&header);

            let data = NoiseEncryptedMessage(data.to_vec());
            kk_client.decrypt_message(&data);
            kk_server.decrypt_message(&data);
        }
    }
});
