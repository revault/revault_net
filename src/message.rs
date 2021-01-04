//! Network Message
//!
//! This module defines the message types and their traits which are used
//! for (de)serializing revault messages for transmission on the network.
//!
//! Please find the specification at
//! https://github.com/re-vault/practical-revault/blob/master/messages.md

use revault_tx::bitcoin::{
    hash_types::Txid,
    secp256k1::{key::PublicKey, Signature},
};
use serde::{Deserialize, Serialize};

/// Opinion struct to be used in watchtower::SpendOpinion and server::SpendOpinions
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct Opinion<'a> {
    /// Spend transaction id
    pub id: Txid,
    /// Acceptance of spend transaction
    pub accepted: bool,
    /// Reason field is set if accept is false, otherwise it is ignored
    pub reason: Option<&'a str>,
    /// ECDSA (secp256k1) signature of this opinion as utf-8 encoded json
    /// with no space and sig:\"\"
    pub sig: Signature,
    /// secp256k1 public key used to produce the above signature
    pub pubkey: PublicKey,
}

/// Watchtower
pub mod watchtower {
    use super::{server::FinalizeSpend, Opinion};
    use revault_tx::bitcoin::{
        hash_types::Txid,
        secp256k1::{key::PublicKey, Signature},
        OutPoint,
    };
    use revault_tx::transactions::SpendTransaction;
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;

    /// Message from a wallet client to share all signatures for a revocation
    /// transaction with its watchtower.
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    pub struct Sig {
        /// A sufficient set of public keys and associated ALL|ANYONECANPAY
        /// bitcoin ECDSA signatures to validate the revocation transaction
        pub signatures: HashMap<PublicKey, Signature>,
        /// Revocation transaction id
        pub txid: Txid,
        /// Deposit outpoint of this vault
        pub deposit_outpoint: OutPoint,
    }

    /// Message from the watchtower to wallet client to acknowledge that it has
    /// sufficient signatures and fees to begin guarding the vault with the
    /// revocation transaction
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    pub struct SigAck {
        /// Result of acknowledgement
        pub ack: bool,
        /// Revocation transaction id
        pub txid: Txid,
    }

    /// Message from watchtower to sync server to learn about spending attempts
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    pub struct GetSpendRequests {}

    /// Request struct to be used in spend_requests message
    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    pub struct Request {
        /// Unsigned signed spend transaction (PSBT format)
        pub unsigned_spend_tx: SpendTransaction,
    }

    /// Message response from watchtower to sync server for get_spend_requests
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    pub struct SpendRequests {
        /// Arbitrarily size array of objects detailing spend requests
        pub requests: Vec<Request>,
    }

    /// Message from a watchtower to the synchronisation server to signal its
    /// acceptance or refusal of a specific spend.
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    pub struct SpendOpinion<'a> {
        /// Watchtower's opinion
        #[serde(borrow)]
        pub opinion: Opinion<'a>,
    }

    /// Regularly sent by a watchtower to the synchronisation server after
    /// having received a spend_request to learn about finalized spending attempts.
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    pub struct GetFinalizedSpends {}

    /// The response to a GetFinalizedSpends.
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    pub struct FinalizedSpends {
        /// Collection of fully signed spend transactions (PSBT format)
        pub requests: Vec<SpendTransaction>,
    }

    impl FinalizedSpends {
        /// Convenience function for sync server to construct FinalizedSpends
        /// from a collection of FinalizeSpend messages
        pub fn new(finalized_spends: Vec<FinalizeSpend>) -> Self {
            let mut requests = Vec::new();
            for req in finalized_spends {
                requests.push(req.signed_spend_tx);
            }
            FinalizedSpends { requests }
        }
    }

    /// Sent by a watchtower to the synchronisation server to signal its
    /// acknowledgement or refusal of a fully-signed spend transaction.
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    pub struct ValidateSpend<'a> {
        /// Watchtower's opinion for the spend transaction
        #[serde(borrow)]
        pub opinion: Opinion<'a>,
    }
}

/// Synchronisation Server
pub mod server {
    use super::Opinion;
    use revault_tx::bitcoin::{
        hash_types::Txid,
        secp256k1::{key::PublicKey, Signature},
    };
    use revault_tx::transactions::SpendTransaction;
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;

    /// Message from a wallet client to sync server to share (at any time) the
    /// signature for an usual transaction with all participants.
    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    pub struct Sig {
        /// Secp256k1 public key used to sign the transaction (hex)
        pub pubkey: PublicKey,
        /// Bitcoin ECDSA signature as hex
        pub signature: Signature,
        /// Txid of the transaction the signature applies to
        pub id: Txid,
    }

    /// An encrypted signature of a transaction
    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    pub struct EncryptedSignature {
        /// Curve25519 public key used to encrypt the signature
        pub pubkey: Vec<u8>,
        /// base64-encoded encrypted Bitcoin ECDSA signature
        pub encrypted_signature: String,
    }

    /// 'Sig' message from a wallet client to sync server to share (at any time) the
    /// signature for an emergency transaction with all participants.
    /// Special-cased as the Emergency transaction signature is encrypted.
    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    pub struct EmergencySig {
        /// Secp256k1 public key used to sign the transaction (hex)
        pub pubkey: PublicKey,
        /// Bitcoin ECDSA signature as hex (for usual transactions)
        pub encrypted_signature: EncryptedSignature,
        /// Txid of the transaction the signature applies to
        pub id: Txid,
    }

    /// Sent by a wallet to retrieve all signatures for a specific transaction
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    pub struct GetSigs {
        /// Transaction id
        pub id: Txid,
    }

    /// Message response to get_sigs from sync server to wallet client with a
    /// (potentially incomplete) mapping of each public key to each signature
    /// required to verify this **usual** transaction
    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    pub struct Sigs {
        /// Mapping of public keys to ECDSA signatures for the requested usual
        /// transaction.
        pub signatures: HashMap<PublicKey, Signature>,
    }

    /// Message response to get_sigs from sync server to wallet client with a
    /// (potentially incomplete) mapping of each public key to each signature
    /// required to verify this **emergency** transaction
    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    pub struct EmergencySigs {
        /// Mapping of public keys to encrypted signatures for the requested emergency
        /// transaction.
        pub encrypted_signatures: HashMap<PublicKey, Vec<EncryptedSignature>>,
    }

    /// Message from a manager to synchronization server to signal their willingness to
    /// spend a vault.
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    pub struct RequestSpend {
        /// Unsigned spend transaction (PSBT format)
        pub unsigned_spend_tx: SpendTransaction,
    }

    /// Message from a manager to poll sync server for watchtowers' agreement
    /// regarding the spend attempt identified by id
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    pub struct GetSpendOpinions {
        /// Spend transaction txid
        pub id: Txid,
    }

    /// Response to a manager from the sync server of watchtowers' agreement
    /// regarding the spend attempt identified by id
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    pub struct SpendOpinions<'a> {
        /// Collection of available opinions from watchtowers
        #[serde(borrow)]
        pub opinions: Vec<Opinion<'a>>,
    }

    /// Sent by a manager to finalize their spending attempt by presenting the
    /// fully-signed spend transaction to the watchtowers
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    pub struct FinalizeSpend {
        /// Fully signed spend transaction
        pub signed_spend_tx: SpendTransaction,
    }

    /// Sent by a manager when polling for watchtowers acknowledgement of the
    /// fully signed transaction spending the vault identified by id
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    pub struct GetSpendValidations {
        /// Spend transaction txid
        pub id: Txid,
    }

    /// Sent by a watchtower to the synchronisation server to signal its
    /// acknowledgement or refusal of a fully-signed spend transaction.
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    pub struct SpendValidations<'a> {
        ///Collection of Watchtowers' signed opinions for the spend transaction
        #[serde(borrow)]
        pub opinions: Vec<Opinion<'a>>,
    }
}

///Cosigning Server
pub mod cosigner {
    use revault_tx::transactions::SpendTransaction;
    use serde::{Deserialize, Serialize};

    /// Message from a manager to a cosigning server who will soon attempt to
    /// unvault and spend a vault utxo
    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    pub struct Sign {
        /// The partially signed unvault transaction
        pub tx: SpendTransaction,
    }

    /// Message returned from the cosigning server to the manager containing
    /// the requested signature
    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    pub struct SignatureMessage {
        /// Cosigning server's signature for the unvault transaction
        pub tx: SpendTransaction,
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, str::FromStr};

    use revault_tx::bitcoin::{
        hash_types::Txid,
        secp256k1::{
            key::{PublicKey, SecretKey},
            Secp256k1, Signature,
        },
        OutPoint,
    };

    use super::cosigner;
    use super::server;
    use super::watchtower;
    use super::Opinion;
    use revault_tx::transactions::SpendTransaction;

    fn get_dummy_pubkey() -> PublicKey {
        let secp_ctx = Secp256k1::new();
        PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap())
    }

    fn get_dummy_sig() -> Signature {
        // from https://github.com/rust-bitcoin/rust-secp256k1/blob/master/src/lib.rs
        Signature::from_compact(&[
            0xdc, 0x4d, 0xc2, 0x64, 0xa9, 0xfe, 0xf1, 0x7a, 0x3f, 0x25, 0x34, 0x49, 0xcf, 0x8c,
            0x39, 0x7a, 0xb6, 0xf1, 0x6f, 0xb3, 0xd6, 0x3d, 0x86, 0x94, 0x0b, 0x55, 0x86, 0x82,
            0x3d, 0xfd, 0x02, 0xae, 0x3b, 0x46, 0x1b, 0xb4, 0x33, 0x6b, 0x5e, 0xcb, 0xae, 0xfd,
            0x66, 0x27, 0xaa, 0x92, 0x2e, 0xfc, 0x04, 0x8f, 0xec, 0x0c, 0x88, 0x1c, 0x10, 0xc4,
            0xc9, 0x42, 0x8f, 0xca, 0x69, 0xc1, 0x32, 0xa2,
        ])
        .expect("compact signatures are 64 bytes; DER signatures are 68-72 bytes")
    }

    fn get_dummy_txid() -> Txid {
        Txid::default()
    }

    fn get_dummy_spend_tx() -> SpendTransaction {
        // A valid psbt from https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki#Encoding
        let psbt_base64 = "cHNidP8BAHUCAAAAASaBcTce3/KF6Tet7qSze3gADAVmy7OtZGQXE8pCFxv2AAAAAAD+////AtPf9QUAAAAAGXapFNDFmQPFusKGh2DpD9UhpGZap2UgiKwA4fUFAAAAABepFDVF5uM7gyxHBQ8k0+65PJwDlIvHh7MuEwAAAQD9pQEBAAAAAAECiaPHHqtNIOA3G7ukzGmPopXJRjr6Ljl/hTPMti+VZ+UBAAAAFxYAFL4Y0VKpsBIDna89p95PUzSe7LmF/////4b4qkOnHf8USIk6UwpyN+9rRgi7st0tAXHmOuxqSJC0AQAAABcWABT+Pp7xp0XpdNkCxDVZQ6vLNL1TU/////8CAMLrCwAAAAAZdqkUhc/xCX/Z4Ai7NK9wnGIZeziXikiIrHL++E4sAAAAF6kUM5cluiHv1irHU6m80GfWx6ajnQWHAkcwRAIgJxK+IuAnDzlPVoMR3HyppolwuAJf3TskAinwf4pfOiQCIAGLONfc0xTnNMkna9b7QPZzMlvEuqFEyADS8vAtsnZcASED0uFWdJQbrUqZY3LLh+GFbTZSYG2YVi/jnF6efkE/IQUCSDBFAiEA0SuFLYXc2WHS9fSrZgZU327tzHlMDDPOXMMJ/7X85Y0CIGczio4OFyXBl/saiK9Z9R5E5CVbIBZ8hoQDHAXR8lkqASECI7cr7vCWXRC+B3jv7NYfysb3mk6haTkzgHNEZPhPKrMAAAAAAAAA";
        serde_json::from_str(&serde_json::to_string(&psbt_base64).unwrap()).unwrap()
    }

    #[test]
    fn serde_watchtower_sig() {
        let pubkey: PublicKey = get_dummy_pubkey();
        let sig: Signature = get_dummy_sig();
        let signatures: HashMap<PublicKey, Signature> = [(pubkey, sig)].iter().cloned().collect();
        let txid: Txid = get_dummy_txid();
        let deposit_outpoint = OutPoint::from_str(
            "3694ef9e8fcd78e9b8165a41e6f5e2b5f10bcd92c6d6e42b3325a850df56cd83:0",
        )
        .unwrap();
        let msg = watchtower::Sig {
            signatures,
            txid,
            deposit_outpoint,
        };
        let serialized_msg = serde_json::to_string(&msg).unwrap();
        let deserialized_msg = serde_json::from_str(&serialized_msg).unwrap();

        assert_eq!(msg, deserialized_msg);
    }

    #[test]
    fn serde_watchtower_sig_ack() {
        let ack = true;
        let txid: Txid = get_dummy_txid();
        let msg = watchtower::SigAck { ack, txid };
        let serialized_msg = serde_json::to_string(&msg).unwrap();
        let deserialized_msg = serde_json::from_str(&serialized_msg).unwrap();

        assert_eq!(msg, deserialized_msg);
    }

    #[test]
    fn serde_watchtower_get_spend_requests() {
        let msg = watchtower::GetSpendRequests {};
        let serialized_msg = serde_json::to_string(&msg).unwrap();
        let deserialized_msg = serde_json::from_str(&serialized_msg).unwrap();

        assert_eq!(msg, deserialized_msg);
    }

    #[test]
    fn serde_watchtower_spend_requests() {
        let unsigned_spend_tx: SpendTransaction = get_dummy_spend_tx();
        let request = watchtower::Request { unsigned_spend_tx };
        let msg = watchtower::SpendRequests {
            requests: vec![request],
        };
        let serialized_msg = serde_json::to_string(&msg).unwrap();
        let deserialized_msg = serde_json::from_str(&serialized_msg).unwrap();

        assert_eq!(msg, deserialized_msg);
    }

    #[test]
    fn serde_watchtower_spend_opinion() {
        let id = get_dummy_txid();
        let accepted = false;
        let reason = Some("teststring");
        let sig = get_dummy_sig();
        let pubkey = get_dummy_pubkey();
        let opinion = Opinion {
            id,
            accepted,
            reason,
            sig,
            pubkey,
        };
        let msg = watchtower::SpendOpinion { opinion };
        let serialized_msg = serde_json::to_string(&msg).unwrap();
        let deserialized_msg = serde_json::from_str(&serialized_msg).unwrap();

        assert_eq!(msg, deserialized_msg);
    }

    #[test]
    fn serde_watchtower_get_finalized_spends() {
        let msg = watchtower::GetFinalizedSpends {};
        let serialized_msg = serde_json::to_string(&msg).unwrap();
        let deserialized_msg = serde_json::from_str(&serialized_msg).unwrap();

        assert_eq!(msg, deserialized_msg);
    }

    #[test]
    fn serde_watchtower_finalized_spends() {
        let signed_spend_tx: SpendTransaction = get_dummy_spend_tx();
        let finalized_spends = vec![server::FinalizeSpend { signed_spend_tx }];
        let msg = watchtower::FinalizedSpends::new(finalized_spends);
        let serialized_msg = serde_json::to_string(&msg).unwrap();
        let deserialized_msg = serde_json::from_str(&serialized_msg).unwrap();

        assert_eq!(msg, deserialized_msg);
    }

    #[test]
    fn serde_watchtower_validate_spend() {
        let id = get_dummy_txid();
        let accepted = false;
        let reason = Some("teststring");
        let sig = get_dummy_sig();
        let pubkey = get_dummy_pubkey();
        let opinion = Opinion {
            id,
            accepted,
            reason,
            sig,
            pubkey,
        };
        let msg = watchtower::ValidateSpend { opinion };
        let serialized_msg = serde_json::to_string(&msg).unwrap();
        let deserialized_msg = serde_json::from_str(&serialized_msg).unwrap();

        assert_eq!(msg, deserialized_msg);
    }

    #[test]
    fn serde_server_sig() {
        let pubkey = get_dummy_pubkey();
        let sig = get_dummy_sig();
        let id = get_dummy_txid();

        // Cleartext signature
        let msg1 = server::Sig {
            pubkey,
            signature: sig.clone(),
            id,
        };
        let serialized_msg = serde_json::to_string(&msg1).unwrap();
        let deserialized_msg = serde_json::from_str(&serialized_msg).unwrap();
        assert_eq!(msg1, deserialized_msg);

        // Encrypted signature
        let encrypted_signature = server::EncryptedSignature {
            pubkey: Vec::new(),
            encrypted_signature: String::new(),
        };
        let msg2 = server::EmergencySig {
            pubkey,
            encrypted_signature,
            id,
        };
        let serialized_msg = serde_json::to_string(&msg2).unwrap();
        let deserialized_msg = serde_json::from_str(&serialized_msg).unwrap();
        assert_eq!(msg2, deserialized_msg);
    }

    #[test]
    fn serde_server_get_sigs() {
        let id = get_dummy_txid();
        let msg = server::GetSigs { id };
        let serialized_msg = serde_json::to_string(&msg).unwrap();
        let deserialized_msg = serde_json::from_str(&serialized_msg).unwrap();

        assert_eq!(msg, deserialized_msg);
    }

    #[test]
    fn serde_server_sigs() {
        let pubkey: PublicKey = get_dummy_pubkey();
        let sig: Signature = get_dummy_sig();
        let signatures: HashMap<PublicKey, Signature> = [(pubkey, sig)].iter().cloned().collect();

        // Cleartext signatures
        let msg1 = server::Sigs { signatures };
        let serialized_msg = serde_json::to_string(&msg1).unwrap();
        let deserialized_msg = serde_json::from_str(&serialized_msg).unwrap();
        assert_eq!(msg1, deserialized_msg);

        // Encrypted signatures
        let encrypted_signature = server::EncryptedSignature {
            pubkey: Vec::new(),
            encrypted_signature: String::new(),
        };
        let encrypted_signatures: HashMap<PublicKey, Vec<server::EncryptedSignature>> =
            [(pubkey, vec![encrypted_signature])]
                .iter()
                .cloned()
                .collect();
        let msg2 = server::EmergencySigs {
            encrypted_signatures,
        };
        let serialized_msg = serde_json::to_string(&msg2).unwrap();
        let deserialized_msg = serde_json::from_str(&serialized_msg).unwrap();
        assert_eq!(msg2, deserialized_msg);

        // No signatures
        let signatures = HashMap::new();
        let msg3 = server::Sigs { signatures };
        let serialized_msg = serde_json::to_string(&msg3).unwrap();
        let deserialized_msg = serde_json::from_str(&serialized_msg).unwrap();
        assert_eq!(msg3, deserialized_msg);
    }

    #[test]
    fn serde_server_request_spend() {
        let unsigned_spend_tx: SpendTransaction = get_dummy_spend_tx();
        let msg = server::RequestSpend { unsigned_spend_tx };
        let serialized_msg = serde_json::to_string(&msg).unwrap();
        let deserialized_msg = serde_json::from_str(&serialized_msg).unwrap();

        assert_eq!(msg, deserialized_msg);
    }

    #[test]
    fn serde_server_get_spend_opinions() {
        let id: Txid = get_dummy_txid();
        let msg = server::GetSpendOpinions { id };
        let serialized_msg = serde_json::to_string(&msg).unwrap();
        let deserialized_msg = serde_json::from_str(&serialized_msg).unwrap();

        assert_eq!(msg, deserialized_msg);
    }

    #[test]
    fn serde_server_spend_opinions() {
        let id = get_dummy_txid();
        let accepted = false;
        let reason = Some("teststring");
        let sig = get_dummy_sig();
        let pubkey = get_dummy_pubkey();
        let opinion = Opinion {
            id,
            accepted,
            reason,
            sig,
            pubkey,
        };
        let msg = server::SpendOpinions {
            opinions: vec![opinion],
        };
        let serialized_msg = serde_json::to_string(&msg).unwrap();
        let deserialized_msg = serde_json::from_str(&serialized_msg).unwrap();

        assert_eq!(msg, deserialized_msg);
    }

    #[test]
    fn serde_server_finalize_spend() {
        let signed_spend_tx: SpendTransaction = get_dummy_spend_tx();
        let msg = server::FinalizeSpend { signed_spend_tx };
        let serialized_msg = serde_json::to_string(&msg).unwrap();
        let deserialized_msg = serde_json::from_str(&serialized_msg).unwrap();

        assert_eq!(msg, deserialized_msg);
    }

    #[test]
    fn serde_server_get_spend_validations() {
        let id: Txid = get_dummy_txid();
        let msg = server::GetSpendValidations { id };
        let serialized_msg = serde_json::to_string(&msg).unwrap();
        let deserialized_msg = serde_json::from_str(&serialized_msg).unwrap();

        assert_eq!(msg, deserialized_msg);
    }

    #[test]
    fn serde_server_spend_validations() {
        let id = get_dummy_txid();
        let accepted = false;
        let reason = Some("teststring");
        let sig = get_dummy_sig();
        let pubkey = get_dummy_pubkey();
        let opinion = Opinion {
            id,
            accepted,
            reason,
            sig,
            pubkey,
        };
        let msg = server::SpendValidations {
            opinions: vec![opinion],
        };
        let serialized_msg = serde_json::to_string(&msg).unwrap();
        let deserialized_msg = serde_json::from_str(&serialized_msg).unwrap();

        assert_eq!(msg, deserialized_msg);
    }

    #[test]
    fn serde_cosigner_sign() {
        let tx = get_dummy_spend_tx();
        let msg = cosigner::Sign { tx };
        let serialized_msg = serde_json::to_string(&msg).unwrap();
        let deserialized_msg = serde_json::from_str(&serialized_msg).unwrap();

        assert_eq!(msg, deserialized_msg);
    }

    #[test]
    fn serder_cosigner_signature_message() {
        let tx = get_dummy_spend_tx();
        let msg = cosigner::SignatureMessage { tx };
        let serialized_msg = serde_json::to_string(&msg).unwrap();
        let deserialized_msg = serde_json::from_str(&serialized_msg).unwrap();

        assert_eq!(msg, deserialized_msg);
    }
}
