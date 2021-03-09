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
    use std::collections::BTreeMap;

    /// Message from a stakeholder to share all signatures for a revocation
    /// transaction with its watchtower.
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    pub struct Sig {
        /// A sufficient set of public keys and associated ALL|ANYONECANPAY
        /// bitcoin ECDSA signatures to validate the revocation transaction
        pub signatures: BTreeMap<PublicKey, Signature>,
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
    use std::collections::BTreeMap;

    /// Message response to get_sigs from sync server to wallet client with a
    /// (potentially incomplete) mapping of each public key to each signature
    /// required to verify this **usual** transaction
    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    pub struct Sigs {
        /// Mapping of public keys to ECDSA signatures for the requested usual
        /// transaction.
        pub signatures: BTreeMap<PublicKey, Signature>,
    }

    /// Sent by a manager to advertise the spend transaction that will eventually
    /// be used for a specific unvault.
    #[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
    pub struct SetSpendTx {
        /// Deposit outpoint of the vault this transaction is spending
        pub deposit_outpoint: OutPoint,
        /// Fully signed spend transaction
        transaction: Vec<u8>,
    }

    impl SetSpendTx {
        /// Create a SetSpendTx message out of a SpendTransaction. The SpendTransaction MUST
        /// have been finalized beforehand!
        pub fn from_spend_tx(deposit_outpoint: OutPoint, tx: SpendTransaction) -> Self {
            let transaction = tx.into_bitcoin_serialized();
            Self {
                deposit_outpoint,
                transaction,
            }
        }

        /// Get the raw spend transaction
        pub fn spend_tx(self) -> Vec<u8> {
            self.transaction
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
    /// the signature for a revocation transaction with all participants.
    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    pub struct Sig {
        /// Secp256k1 public key used to sign the transaction (hex)
        pub pubkey: PublicKey,
        /// Bitcoin ECDSA signature as hex
        pub signature: Signature,
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
        pub tx: Option<SpendTransaction>,
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, str::FromStr};

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
        let psbt_base64 = "cHNidP8BAGcCAAAAAY74R7yfKjYatj96vo5Ww2nRXnMLqJZ0sJtCZ0vUDJT1AAAAAADNVgAAAoDYAQAAAAAAIgAgrhve44jyE2BUeXInsUqYPSjeKfUi8+vcTiX9K649nlIBAAAAAAAAAAAAAAAAAAEBK6BK9QUAAAAAIgAgGOT4nZS2eDtYm83Cvrva0Ozxmrw4Wjin73s81+Z/MfEBAwQBAAAAAQX9YgJTIQJXWghCPRbOUhpx+hi93OfpK75maJRYRC38QR4f7+NtFiECM9/45YqHN25XccUBgRIDEcbyVEgt7j61+c9r3RZ7FzohAriewns/EcwKUVDvv1bxr790pkzQRzmqfV3dQ9mzBjaQU65kdqkUqOUtXIDgEzokTmljuXvjUVK6PKqIrGt2qRSxhJ72lPFm92bL1zs0fxxSxgvWIIisbJNrdqkUH5eaO3DdSZU5iyaVBAxs4jQpiiaIrGyTa3apFORRbu2KExrgnCCww5w9TraaoolAiKxsk2t2qRTdO8BPO/zd71a6yb+Cns88TZKG84isbJNrdqkU32Y5t5RL0rYBZZvHWmii6eTcgZ+IrGyTa3apFK83DFJxO+ke61QLvGNyYnmSwKrDiKxsk2t2qRQOTi7K/HfcXcC5iBLjCnMWcMWjIYisbJNYh2dYIQLR/ezgE85uXQeHPU/DkO9OMViCc8qtX1GT1B+pC3O4ASECx3y8Y+ejFiUsobbCiYlAU3h87Q7y+QhADwLFygARZXchAiQAGsW+t/RQ0AJ1axuUM9e58WBlzItzzI4xB8sPnMrsIQKnh96esMFOEyF0tbKBXWmAtff+mxSOoyQVefv/JN/vhSEDiQaTfG58TKdD2N4DbB+wCd3Sz04D4Psle+84rmIW51ghAzFWj+Qs+0gWprDMs3Aat9f5wMZuZaZth1AAtHbe2NbxIQL8522r0lMYLHkL+h2yus2uJP8y6N28+cwpWyaTFNnP+CECdjQgoJBQYwTi7KPMwt1RBcdP0KnnWdYNCSkUmtF972hYrwLOVrJoAAEBaVEhAldaCEI9Fs5SGnH6GL3c5+krvmZolFhELfxBHh/v420WIQIz3/jlioc3bldxxQGBEgMRxvJUSC3uPrX5z2vdFnsXOiECuJ7Cez8RzApRUO+/VvGvv3SmTNBHOap9Xd1D2bMGNpBTrgAA";
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
        let signatures: BTreeMap<PublicKey, Signature> = [(pubkey, sig)].iter().cloned().collect();
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
            transaction: get_dummy_spend_tx().into_bitcoin_serialized(),
        };
        roundtrip!(msg);
    }

    #[test]
    fn serde_server_sig() {
        let pubkey = get_dummy_pubkey();
        let signature = get_dummy_sig();
        let id = get_dummy_txid();

        // Cleartext signature
        let msg = server::FromStakeholder::Sig(server::Sig {
            pubkey,
            signature,
            id,
        });
        roundtrip!(msg);
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
        let sig = get_dummy_sig();
        let signatures = [(pubkey, sig)].iter().cloned().collect();

        // With signatures
        let msg = server::Sigs { signatures };
        roundtrip!(msg);

        // Without signatures
        let signatures = BTreeMap::new();
        let msg = server::Sigs { signatures };
        roundtrip!(msg);
    }

    #[test]
    fn serde_server_request_spend() {
        let deposit_outpoint = OutPoint::from_str(
            "6e4977728e7100db80c30751f27cf834b7a1e02d083a4338874e48d1f3694446:0",
        )
        .unwrap();
        let unsigned_spend_tx: SpendTransaction = get_dummy_spend_tx();
        let msg = server::SetSpendTx::from_spend_tx(deposit_outpoint, unsigned_spend_tx);
        roundtrip!(msg);
    }

    #[test]
    fn serde_cosigner_sign() {
        let tx = get_dummy_spend_tx();
        let msg = cosigner::Sign { tx };
        roundtrip!(msg);
    }

    #[test]
    fn serde_cosigner_signature_message() {
        let tx = Some(get_dummy_spend_tx());
        let msg = cosigner::SignatureMessage { tx };
        roundtrip!(msg);
    }
}
