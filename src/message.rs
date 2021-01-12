//! Network Message
//!
//! This module defines the message types and their traits which are used
//! for (de)serializing revault messages for transmission on the network.
//!
//! Please find the specification at
//! https://github.com/re-vault/practical-revault/blob/master/messages.md

/// Watchtower
pub mod watchtower {
    use revault_tx::bitcoin::{
        hash_types::Txid,
        secp256k1::{key::PublicKey, Signature},
        OutPoint,
    };
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;

    /// Message from a stakeholder to share all signatures for a revocation
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

    /// Message from the watchtower to stakeholder to acknowledge that it has
    /// sufficient signatures and fees to begin guarding the vault with the
    /// revocation transaction
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    pub struct SigAck {
        /// Result of acknowledgement
        pub ack: bool,
        /// Revocation transaction id
        pub txid: Txid,
    }
}

/// Synchronisation Server
pub mod server {
    use revault_tx::{
        bitcoin::{
            hash_types::Txid,
            secp256k1::{key::PublicKey, Signature},
            OutPoint,
        },
        transactions::{RevaultTransaction, SpendTransaction},
    };
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;

    /// Some of the signatures we exchange may be encrypted (emergency tx ones).
    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    pub enum RevaultSignature {
        /// A plaintext (hex) signature
        PlaintextSig(Signature),
        /// An encryped (b64) signature
        EncryptedSig {
            /// Curve25519 public key used to encrypt the signature
            pubkey: Vec<u8>,
            /// Encrypted Bitcoin ECDSA signature
            encrypted_signature: Vec<u8>,
        },
    }

    /// Message response to get_sigs from sync server to wallet client with a
    /// (potentially incomplete) mapping of each public key to each signature
    /// required to verify this **usual** transaction
    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    pub struct Sigs {
        /// Mapping of public keys to ECDSA signatures for the requested usual
        /// transaction.
        pub signatures: HashMap<PublicKey, RevaultSignature>,
    }

    /// Sent by a manager to advertise the spend transaction that will eventually
    /// be used for a specific unvault.
    #[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
    pub struct SetSpendTx {
        /// Fully signed spend transaction
        transaction: Vec<u8>,
    }

    impl SetSpendTx {
        /// Create a SetSpendTx message out of a SpendTransaction. The SpendTransaction MUST
        /// have been finalized beforehand!
        pub fn from_spend_tx(tx: SpendTransaction) -> Result<Self, revault_tx::Error> {
            // FIXME: implement into_bitcoin_serialized upstream!
            tx.as_bitcoin_serialized()
                .map(|transaction| Self { transaction })
        }
    }

    /// Sent by a watchtower to the synchronisation server after an unvault
    /// event to learn about the spend transaction.
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    pub struct GetSpendTx {
        /// Outpoint designing the deposit utxo that created the vault this
        /// spend tx is spending.
        pub deposit_outpoint: OutPoint,
    }

    /// The response to the [GetSpendTx] request.
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    pub struct SpendTx {
        /// The Bitcoin-serialized Spend transaction. The sync server isn't
        /// creating it so there is no point to create it from_spend_tx().
        pub transaction: Vec<u8>,
    }

    /// Message from a stakeholder client to sync server to share (at any time)
    /// the signature for an usual transaction with all participants.
    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    pub struct Sig {
        /// Secp256k1 public key used to sign the transaction (hex)
        pub pubkey: PublicKey,
        /// Bitcoin ECDSA signature as hex
        pub signature: RevaultSignature,
        /// Txid of the transaction the signature applies to
        pub id: Txid,
    }

    /// Sent by a wallet to retrieve all signatures for a specific transaction
    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    pub struct GetSigs {
        /// Transaction id
        pub id: Txid,
    }

    /// A message sent from a stakeholder to the Coordinator
    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    #[serde(untagged)]
    pub enum FromStakeholder {
        /// Stakeholders can push signatures
        Sig(Sig),
        /// Stakeholders can fetch signatures
        GetSigs(GetSigs),
    }

    /// A message sent from a manager to the Coordinator
    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    #[serde(untagged)]
    pub enum FromManager {
        /// Managers can set a spend transaction
        SetSpend(SetSpendTx),
        /// Managers can fetch pre-signed transaction signatures
        GetSigs(GetSigs),
    }
}

/// Cosigning Server
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

    use revault_tx::{
        bitcoin::{
            hash_types::Txid,
            secp256k1::{
                key::{PublicKey, SecretKey},
                Secp256k1, Signature,
            },
            OutPoint,
        },
        transactions::{RevaultTransaction, SpendTransaction},
    };

    use super::cosigner;
    use super::server;
    use super::watchtower;

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

    macro_rules! roundtrip {
        ($msg:ident) => {
            let serialized_msg = serde_json::to_string(&$msg).unwrap();
            let deserialized_msg = serde_json::from_str(&serialized_msg).unwrap();
            assert_eq!($msg, deserialized_msg);
        };
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
        roundtrip!(msg);
    }

    #[test]
    fn serde_watchtower_sig_ack() {
        let ack = true;
        let txid: Txid = get_dummy_txid();
        let msg = watchtower::SigAck { ack, txid };
        roundtrip!(msg);
    }

    #[test]
    fn serde_watchtower_get_spend_tx() {
        let msg = server::GetSpendTx {
            deposit_outpoint: OutPoint::from_str(
                "6a276a96807dd45ceed9cbd6fd48b5edf185623b23339a1643e19e8dcbf2e474:0",
            )
            .unwrap(),
        };
        roundtrip!(msg);

        // Response
        let msg = server::SpendTx {
            transaction: get_dummy_spend_tx().as_bitcoin_serialized().unwrap(),
        };
        roundtrip!(msg);
    }

    #[test]
    fn serde_server_sig() {
        let pubkey = get_dummy_pubkey();
        let sig = get_dummy_sig();
        let id = get_dummy_txid();

        // Cleartext signature
        let msg1 = server::FromStakeholder::Sig(server::Sig {
            pubkey,
            signature: server::RevaultSignature::PlaintextSig(sig),
            id,
        });
        roundtrip!(msg1);

        // Encrypted signature
        let signature = server::RevaultSignature::EncryptedSig {
            pubkey: Vec::new(),
            encrypted_signature: Vec::new(),
        };
        let msg2 = server::FromStakeholder::Sig(server::Sig {
            pubkey,
            signature,
            id,
        });
        roundtrip!(msg2);
    }

    #[test]
    fn serde_server_get_sigs() {
        let id = get_dummy_txid();
        let msg = server::FromStakeholder::GetSigs(server::GetSigs { id });
        roundtrip!(msg);
    }

    #[test]
    fn serde_server_sigs() {
        let pubkey: PublicKey = get_dummy_pubkey();
        let sig = server::RevaultSignature::PlaintextSig(get_dummy_sig());
        let signatures: HashMap<PublicKey, server::RevaultSignature> =
            [(pubkey, sig)].iter().cloned().collect();

        // Cleartext signatures
        let msg1 = server::Sigs { signatures };
        roundtrip!(msg1);

        // Encrypted signatures
        let encrypted_signature = server::RevaultSignature::EncryptedSig {
            pubkey: Vec::new(),
            encrypted_signature: Vec::new(),
        };
        let signatures = [(pubkey, encrypted_signature)].iter().cloned().collect();
        let msg2 = server::Sigs { signatures };
        roundtrip!(msg2);

        // No signatures
        let signatures = HashMap::new();
        let msg3 = server::Sigs { signatures };
        roundtrip!(msg3);
    }

    #[test]
    fn serde_server_request_spend() {
        let unsigned_spend_tx: SpendTransaction = get_dummy_spend_tx();
        let msg = server::SetSpendTx::from_spend_tx(unsigned_spend_tx).unwrap();
        roundtrip!(msg);
    }

    #[test]
    fn serde_cosigner_sign() {
        let tx = get_dummy_spend_tx();
        let msg = cosigner::Sign { tx };
        roundtrip!(msg);
    }

    #[test]
    fn serder_cosigner_signature_message() {
        let tx = get_dummy_spend_tx();
        let msg = cosigner::SignatureMessage { tx };
        roundtrip!(msg);
    }
}
