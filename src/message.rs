//! Network Message
//!
//! This module defines the message types and their traits which are used
//! for (de)serializing revault messages for transmission on the network.
//!
//! Please find the specification at
//! https://github.com/re-vault/practical-revault/blob/master/messages.md

use bitcoin::hashes::sha256::Hash as Sha256;
use serde::{Deserialize, Serialize};

/// New type for Sha256(Txid) used as a way to uniquely identify transactions
/// while hiding the actual Txid.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct MaskedTxid(Sha256);

///Watchtower
mod watchtower {
    use super::MaskedTxid;
    use bitcoin::{
        hash_types::Txid,
        secp256k1::{key::PublicKey, Signature},
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
        pub params: HashMap<PublicKey, Signature>,
        /// The txid of the revocation transaction
        pub txid: Txid,
        /// Vault transaction id
        pub vault_txid: Txid,
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
        /// Fully signed spend transaction
        pub transaction: SpendTransaction,
        /// Timestamp of when the request was created
        pub timestamp: i64,
        /// SHA256(Vault Txid) of the vault transaction that is to be spent from
        pub vault_id: MaskedTxid,
    }

    /// Message response for get_spend_requests
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    pub struct SpendRequests {
        /// Arbitrarily size array of objects detailing spend requests
        pub requests: Vec<Request>,
    }

    /// Opinion struct to be used in spend_opinions message
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    pub struct Opinion<'a> {
        /// Acceptance of spend transaction
        pub accepted: bool,
        /// Reason field is set if accept is false, otherwise it is ignored
        pub reason: Option<&'a str>,
        /// ECDSA (secp256k1) signature of this opinion as utf-8 encoded json
        /// with no space and sig:\"\"
        pub sig: Signature,
    }

    /// Message from a watchtower to the synchronisation server to signal its
    /// acceptance or refusal of a specific spend.
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    pub struct SpendOpinion<'a> {
        /// SHA256(Vault Txid) of the vault transaction that is to be spent from
        pub vault_id: MaskedTxid,
        /// Opinion on the vault transaction
        #[serde(borrow)]
        pub opinion: Opinion<'a>,
    }

    /// Message from a manager to watchtower to signal their willingness to
    /// spend a vault.
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    pub struct RequestSpend(pub Request);

    /// Message from a manager to poll watchtowers for agreement regarding the
    /// spend attempt identified by vault_id
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    pub struct GetSpendOpinions {
        /// SHA256(Vault Txid) of the vault transaction that is to be spent from
        pub vault_id: MaskedTxid,
    }

    /// Message from a watchtower to the synchronisation server to signal its
    /// acceptance or refusal of a specific spend.
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    pub struct SpendOpinions<'a> {
        /// SHA256(Vault Txid) of the vault transaction that is to be spent from
        pub vault_id: MaskedTxid,
        /// Arbitrarily size array of objects detailing opinions on spend requests
        #[serde(borrow)]
        pub opinions: Vec<Opinion<'a>>,
    }
}

///Synchronisation Server
mod server {
    use super::MaskedTxid;
    use bitcoin::secp256k1::{key::PublicKey, Signature};
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;

    /// Message from a wallet client to sync server to share (at any time) the
    ///  signature for a transaction with all participants.
    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    pub struct Sig {
        /// Secp256k1 public key used to sign the transaction (hex)
        pub pubkey: PublicKey,
        /// Bitcoin ECDSA signature as hex
        pub sig: Signature,
        /// SHA256(Txid) of the transaction the signature applies to
        pub id: MaskedTxid,
    }

    /// Message from a wallet client to the sync server to retrieve all
    /// signatures for a specific transaction.
    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    pub struct GetSigs {
        /// Transaction uid
        pub id: MaskedTxid,
    }

    /// Message response to get_sigs from sync server to wallet client with a
    /// (potentially incomplete) mapping of each public key to each signature
    /// required to verify this transaction
    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    pub struct Sigs {
        /// Mapping of public keys to ECDSA signatures for the requested transaction
        pub signatures: HashMap<PublicKey, Signature>,
    }

    /// Message from wallet client to sync server to announce that a signature
    /// was not valid for the given transaction
    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    pub struct ErrSig {
        /// Transaction uid for which a signature verification failed
        pub id: MaskedTxid,
    }
}

///Cosigning Server
mod cosigner {
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
    use std::collections::HashMap;

    use bitcoin::{
        hash_types::Txid,
        hashes::{sha256::Hash as Sha256, Hash, HashEngine},
        secp256k1::{
            key::{PublicKey, SecretKey},
            Secp256k1, Signature,
        },
    };

    use super::cosigner;
    use super::server;
    use super::watchtower;
    use super::MaskedTxid;
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
        bitcoin::Txid::default()
    }

    fn get_dummy_spend_tx() -> SpendTransaction {
        // A valid psbt from https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki#Encoding
        let psbt_base64 = "cHNidP8BAHUCAAAAASaBcTce3/KF6Tet7qSze3gADAVmy7OtZGQXE8pCFxv2AAAAAAD+////AtPf9QUAAAAAGXapFNDFmQPFusKGh2DpD9UhpGZap2UgiKwA4fUFAAAAABepFDVF5uM7gyxHBQ8k0+65PJwDlIvHh7MuEwAAAQD9pQEBAAAAAAECiaPHHqtNIOA3G7ukzGmPopXJRjr6Ljl/hTPMti+VZ+UBAAAAFxYAFL4Y0VKpsBIDna89p95PUzSe7LmF/////4b4qkOnHf8USIk6UwpyN+9rRgi7st0tAXHmOuxqSJC0AQAAABcWABT+Pp7xp0XpdNkCxDVZQ6vLNL1TU/////8CAMLrCwAAAAAZdqkUhc/xCX/Z4Ai7NK9wnGIZeziXikiIrHL++E4sAAAAF6kUM5cluiHv1irHU6m80GfWx6ajnQWHAkcwRAIgJxK+IuAnDzlPVoMR3HyppolwuAJf3TskAinwf4pfOiQCIAGLONfc0xTnNMkna9b7QPZzMlvEuqFEyADS8vAtsnZcASED0uFWdJQbrUqZY3LLh+GFbTZSYG2YVi/jnF6efkE/IQUCSDBFAiEA0SuFLYXc2WHS9fSrZgZU327tzHlMDDPOXMMJ/7X85Y0CIGczio4OFyXBl/saiK9Z9R5E5CVbIBZ8hoQDHAXR8lkqASECI7cr7vCWXRC+B3jv7NYfysb3mk6haTkzgHNEZPhPKrMAAAAAAAAA";
        serde_json::from_str(&serde_json::to_string(&psbt_base64).unwrap()).unwrap()
    }

    fn sha256(x: &[u8]) -> Sha256 {
        let mut sha = Sha256::engine();
        sha.input(x);
        Sha256::from_engine(sha)
    }

    #[test]
    fn serde_watchtower_sig() {
        let pubkey: PublicKey = get_dummy_pubkey();
        let sig: Signature = get_dummy_sig();
        let params: HashMap<PublicKey, Signature> = [(pubkey, sig)].iter().cloned().collect();
        let txid: Txid = get_dummy_txid();
        let vault_txid: Txid = get_dummy_txid();
        let msg = watchtower::Sig {
            params,
            txid,
            vault_txid,
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
        let transaction: SpendTransaction = get_dummy_spend_tx();
        let timestamp: i64 = 1000000;
        let txid = get_dummy_txid().to_string();
        let vault_txid = sha256(&txid.as_bytes());
        let vault_id = MaskedTxid(vault_txid);
        let request = watchtower::Request {
            transaction,
            timestamp,
            vault_id,
        };
        let msg = watchtower::SpendRequests {
            requests: vec![request],
        };
        let serialized_msg = serde_json::to_string(&msg).unwrap();
        let deserialized_msg = serde_json::from_str(&serialized_msg).unwrap();

        assert_eq!(msg, deserialized_msg);
    }

    #[test]
    fn serde_watchtower_spend_opinion() {
        let txid = get_dummy_txid().to_string();
        let vault_txid = sha256(&txid.as_bytes());
        let vault_id = MaskedTxid(vault_txid);
        let accepted = false;
        let reason = Some("teststring");
        let sig = get_dummy_sig();
        let opinion = watchtower::Opinion {
            accepted,
            reason,
            sig,
        };
        let msg = watchtower::SpendOpinion { vault_id, opinion };
        let serialized_msg = serde_json::to_string(&msg).unwrap();
        let deserialized_msg = serde_json::from_str(&serialized_msg).unwrap();

        assert_eq!(msg, deserialized_msg);
    }

    #[test]
    fn serde_watchtower_request_spend() {
        let transaction = get_dummy_spend_tx();
        let timestamp: i64 = 1000000;
        let txid = get_dummy_txid().to_string();
        let vault_txid = sha256(&txid.as_bytes());
        let vault_id = MaskedTxid(vault_txid);
        let req = watchtower::Request {
            transaction,
            timestamp,
            vault_id,
        };
        let msg = watchtower::RequestSpend(req);
        let serialized_msg = serde_json::to_string(&msg).unwrap();
        let deserialized_msg = serde_json::from_str(&serialized_msg).unwrap();

        assert_eq!(msg, deserialized_msg);
    }

    #[test]
    fn serde_watchtower_get_spend_opinions() {
        let txid = get_dummy_txid().to_string();
        let vault_txid = sha256(&txid.as_bytes());
        let vault_id = MaskedTxid(vault_txid);
        let msg = watchtower::GetSpendOpinions { vault_id };
        let serialized_msg = serde_json::to_string(&msg).unwrap();
        let deserialized_msg = serde_json::from_str(&serialized_msg).unwrap();

        assert_eq!(msg, deserialized_msg);
    }

    #[test]
    fn serde_watchtower_opinion() {
        let accepted = false;
        let reason = Some("teststring");
        let sig = get_dummy_sig();
        let op = watchtower::Opinion {
            accepted,
            reason,
            sig,
        };
        let txid = get_dummy_txid().to_string();
        let vault_txid = sha256(&txid.as_bytes());
        let vault_id = MaskedTxid(vault_txid);
        let msg = watchtower::SpendOpinions {
            vault_id,
            opinions: vec![op],
        };
        let serialized_msg = serde_json::to_string(&msg).unwrap();
        let deserialized_msg = serde_json::from_str(&serialized_msg).unwrap();

        assert_eq!(msg, deserialized_msg);
    }

    #[test]
    fn serde_server_sig() {
        let pubkey = get_dummy_pubkey();
        let sig = get_dummy_sig();
        let txid = get_dummy_txid().to_string();
        let id = MaskedTxid(sha256(&txid.as_bytes()));
        let msg = server::Sig { pubkey, sig, id };
        let serialized_msg = serde_json::to_string(&msg).unwrap();
        let deserialized_msg = serde_json::from_str(&serialized_msg).unwrap();

        assert_eq!(msg, deserialized_msg);
    }

    #[test]
    fn serde_server_get_sigs() {
        let txid = get_dummy_txid().to_string();
        let id = MaskedTxid(sha256(&txid.as_bytes()));
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
        let msg = server::Sigs { signatures };
        let serialized_msg = serde_json::to_string(&msg).unwrap();
        let deserialized_msg = serde_json::from_str(&serialized_msg).unwrap();

        assert_eq!(msg, deserialized_msg);
    }

    #[test]
    fn serde_server_err_sig() {
        let txid = get_dummy_txid().to_string();
        let id = MaskedTxid(sha256(&txid.as_bytes()));
        let msg = server::ErrSig { id };
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
