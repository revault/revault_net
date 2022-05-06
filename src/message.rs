//! Network Message
//!
//! This module defines the message types and their traits which are used
//! for (de)serializing revault messages for transmission on the network.
//!
//! Please find the specification at
//! https://github.com/re-vault/practical-revault/blob/master/messages.md

use serde::{Deserialize, Serialize};

/// A JSONRPC-like request, as specified in [practical-revault](https://github.com/revault/practical-revault/blob/master/messages.md)
#[allow(missing_docs)]
#[derive(Debug, PartialEq, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum Request<'a> {
    WtSigs {
        method: &'a str,
        params: watchtower::Sigs,
        id: u32,
    },
    SetSpendTx {
        method: &'a str,
        params: coordinator::SetSpendTx,
        id: u32,
    },
    GetSpendTx {
        method: &'a str,
        params: coordinator::GetSpendTx,
        id: u32,
    },
    CoordSig {
        method: &'a str,
        params: coordinator::Sig,
        id: u32,
    },
    GetSigs {
        method: &'a str,
        params: coordinator::GetSigs,
        id: u32,
    },
    Sign {
        method: &'a str,
        params: cosigner::SignRequest,
        id: u32,
    },
}

impl<'a> Request<'a> {
    /// Get the parameters of this request
    pub fn params(self) -> RequestParams {
        match self {
            Request::WtSigs { params, .. } => RequestParams::WtSigs(params),
            Request::SetSpendTx { params, .. } => RequestParams::SetSpendTx(params),
            Request::GetSpendTx { params, .. } => RequestParams::GetSpendTx(params),
            Request::CoordSig { params, .. } => RequestParams::CoordSig(params),
            Request::GetSigs { params, .. } => RequestParams::GetSigs(params),
            Request::Sign { params, .. } => RequestParams::Sign(params),
        }
    }

    /// Get the id of this request
    pub fn id(&self) -> u32 {
        match self {
            Request::WtSigs { id, .. } => *id,
            Request::SetSpendTx { id, .. } => *id,
            Request::GetSpendTx { id, .. } => *id,
            Request::CoordSig { id, .. } => *id,
            Request::GetSigs { id, .. } => *id,
            Request::Sign { id, .. } => *id,
        }
    }
}

/// All params types that can possibly be sent through a Request
#[allow(missing_docs)]
#[derive(Debug, PartialEq, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum RequestParams {
    WtSigs(watchtower::Sigs),
    SetSpendTx(coordinator::SetSpendTx),
    GetSpendTx(coordinator::GetSpendTx),
    CoordSig(coordinator::Sig),
    GetSigs(coordinator::GetSigs),
    Sign(cosigner::SignRequest),
}

// Implement From(param type) for a Request
macro_rules! impl_to_request {
    ($message_struct:ident, $message_name:literal, $enum_variant:ident) => {
        impl From<$message_struct> for Request<'_> {
            fn from(params: $message_struct) -> Self {
                Self::$enum_variant {
                    method: $message_name,
                    params,
                    id: sodiumoxide::randombytes::randombytes_uniform(u32::MAX),
                }
            }
        }
    };
}

/// All result types that can possibly be returned by a Response
#[allow(missing_docs)]
#[derive(Debug, PartialEq, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ResponseResult {
    WtSigs(watchtower::SigsResult),
    Sigs(coordinator::Sigs),
    Sig(coordinator::SigResult),
    SetSpend(coordinator::SetSpendResult),
    SpendTx(coordinator::SpendTx),
    SignResult(cosigner::SignResult),
}

/// A JSONRPC-like response, as specified in [practical-revault](https://github.com/revault/practical-revault/blob/master/messages.md)
#[allow(missing_docs)]
#[derive(Debug, PartialEq, Clone, Deserialize, Serialize)]
pub struct Response<T> {
    pub result: T,
    pub id: u32,
}

/// Messages related to the communication with the Watchtower(s)
pub mod watchtower {
    use super::Request;
    use bitcoin::{
        secp256k1::{key::PublicKey, Signature},
        util::bip32,
        Amount, OutPoint,
    };
    use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
    use std::{collections::BTreeMap, convert::From, str::FromStr};

    /// Serialize an amount as sats
    pub fn ser_amount_sat<S: Serializer>(amount: &Amount, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&amount.as_sat().to_string())
    }

    /// Deserialize an amount from sats
    pub fn deser_amount_from_sats<'de, D>(deserializer: D) -> Result<Amount, D::Error>
    where
        D: Deserializer<'de>,
    {
        let sats: u64 =
            u64::from_str(&String::deserialize(deserializer)?).map_err(de::Error::custom)?;
        Ok(Amount::from_sat(sats))
    }

    /// The key in the mapping from feerate to Cancel signatures. (De)serializes an amount in
    /// satoshis as a string.
    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Ord, PartialOrd, Eq)]
    pub struct CancelFeerate(
        #[serde(
            serialize_with = "ser_amount_sat",
            deserialize_with = "deser_amount_from_sats"
        )]
        pub Amount,
    );

    /// A sufficient set of public keys and associated ALL|ANYONECANPAY Bitcoin
    /// ECDSA signatures for each transaction type.
    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    pub struct Signatures {
        /// Emergency transaction signatures
        pub emergency: BTreeMap<PublicKey, Signature>,
        /// Mapping from feerates to Cancel transaction signatures
        pub cancel: BTreeMap<CancelFeerate, BTreeMap<PublicKey, Signature>>,
        /// Unvault Emergency transaction signatures
        pub unvault_emergency: BTreeMap<PublicKey, Signature>,
    }

    /// Message from a stakeholder to share the signatures for all revocation
    /// transactions with its watchtower.
    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    pub struct Sigs {
        /// All transactions' signatures
        pub signatures: Signatures,
        /// Deposit outpoint of this vault
        pub deposit_outpoint: OutPoint,
        /// Derivation index of the deposit descriptor
        pub derivation_index: bip32::ChildNumber,
    }
    impl_to_request!(Sigs, "sigs", WtSigs);

    /// Message from the watchtower to stakeholder to acknowledge that it checked
    /// and stored the revocation transaction signatures.
    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    pub struct SigsResult {
        /// Result of acknowledgement
        pub ack: bool,
    }
}

/// Messages related to the communication with the Coordinator
pub mod coordinator {
    use super::{Deserialize, Request, Serialize};
    use bitcoin::{
        hash_types::Txid,
        secp256k1::{key::PublicKey, Signature},
        OutPoint, Transaction,
    };
    use revault_tx::transactions::{RevaultTransaction, SpendTransaction};
    use std::collections::BTreeMap;
    use std::convert::From;

    mod serde_tx_base64_nullable {
        use revault_tx::bitcoin::{consensus::encode, Transaction};
        use serde::{self, Deserialize, Deserializer, Serialize, Serializer};
        use sodiumoxide::base64::{self, Variant};

        pub fn serialize<S>(tx: &Option<Transaction>, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            tx.as_ref()
                .map(|t| base64::encode(encode::serialize(t), Variant::Original))
                .serialize(serializer)
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Transaction>, D::Error>
        where
            D: Deserializer<'de>,
        {
            <Option<String>>::deserialize(deserializer)?
                .map(|s| {
                    base64::decode(&s, Variant::Original)
                        .map_err(|_| serde::de::Error::custom("Invalid base64 string"))
                })
                .transpose()?
                .map(|bytes| {
                    encode::deserialize::<Transaction>(&bytes).map_err(serde::de::Error::custom)
                })
                .transpose()
        }
    }

    mod serde_tx_base64 {
        use revault_tx::bitcoin::{consensus::encode, Transaction};
        use serde::{self, Deserialize, Deserializer, Serialize, Serializer};
        use sodiumoxide::base64::{self, Variant};

        pub fn serialize<S>(tx: &Transaction, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let base64_str = base64::encode(encode::serialize(tx), Variant::Original);
            base64_str.serialize(serializer)
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<Transaction, D::Error>
        where
            D: Deserializer<'de>,
        {
            let s = String::deserialize(deserializer)?;
            let bytes = &base64::decode(&s, Variant::Original)
                .map_err(|_| serde::de::Error::custom("Invalid base64 string"))?;
            encode::deserialize::<Transaction>(&bytes).map_err(serde::de::Error::custom)
        }
    }

    /// Sent by a wallet to retrieve all signatures for a specific transaction
    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    pub struct GetSigs {
        /// Transaction id
        pub id: Txid,
    }
    impl_to_request!(GetSigs, "get_sigs", GetSigs);

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
    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    pub struct SetSpendTx {
        /// Deposit outpoints of the vault this transaction is spending
        pub deposit_outpoints: Vec<OutPoint>,
        /// Fully signed spend transaction, as hex
        #[serde(with = "serde_tx_base64")]
        transaction: Transaction,
    }
    impl_to_request!(SetSpendTx, "set_spend_tx", SetSpendTx);

    impl SetSpendTx {
        /// Create a SetSpendTx message out of a SpendTransaction.
        ///
        /// The SpendTransaction MUST have been finalized beforehand or it'll panic.
        pub fn from_spend_tx(deposit_outpoints: Vec<OutPoint>, tx: SpendTransaction) -> Self {
            assert!(tx.is_finalized());
            let transaction = tx.into_psbt().extract_tx();
            Self {
                deposit_outpoints,
                transaction,
            }
        }

        /// Get the raw spend transaction
        pub fn spend_tx(self) -> Transaction {
            self.transaction
        }
    }

    /// Response to [SetSpendTx] by the coordinator, `ack` is `true` if it claims to have
    /// succesfully stored the Spend tx.
    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    pub struct SetSpendResult {
        /// Result of acknowledgement
        pub ack: bool,
    }

    /// Sent by a watchtower to the synchronisation server after an unvault
    /// event to learn about the spend transaction.
    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    pub struct GetSpendTx {
        /// Outpoint designing the deposit utxo that created the vault this
        /// spend tx is spending.
        pub deposit_outpoint: OutPoint,
    }
    impl_to_request!(GetSpendTx, "get_spend_tx", GetSpendTx);

    /// The response to the [GetSpendTx] request.
    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    pub struct SpendTx {
        /// The Bitcoin-serialized Spend transaction. The sync server isn't
        /// creating it so there is no point to create it from_spend_tx().
        #[serde(with = "serde_tx_base64_nullable")]
        pub transaction: Option<Transaction>,
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
    impl_to_request!(Sig, "sig", CoordSig);

    /// Response to [SigResult] by the coordinator, `ack` is `true` if it claims to have
    /// succesfully stored the Spend tx.
    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    pub struct SigResult {
        /// Result of acknowledgement
        pub ack: bool,
    }
}

/// Messages related to the communication with the Cosigning Server(s)
pub mod cosigner {
    use super::{Deserialize, Request, Serialize};
    use revault_tx::transactions::SpendTransaction;
    use std::convert::From;

    /// Message from a manager to a cosigning server who will soon attempt to
    /// unvault and spend a vault utxo
    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    pub struct SignRequest {
        /// The partially signed unvault transaction
        pub tx: SpendTransaction,
    }
    impl_to_request!(SignRequest, "sign", Sign);

    /// Message returned from the cosigning server to the manager containing
    /// the requested signature
    #[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
    pub struct SignResult {
        /// Cosigning server's signature for the unvault transaction
        pub tx: Option<SpendTransaction>,
    }
}

#[cfg(test)]
mod tests {
    use super::{Request, Response, ResponseResult};
    use std::{collections::BTreeMap, str::FromStr};

    use revault_tx::{
        bitcoin::{
            hash_types::Txid,
            secp256k1::{
                key::{PublicKey, SecretKey},
                Secp256k1, Signature,
            },
            Amount, OutPoint,
        },
        transactions::{RevaultTransaction, SpendTransaction},
    };

    use super::coordinator;
    use super::cosigner;
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

    fn get_dummy_spend_tx() -> SpendTransaction {
        let psbt_base64 = "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";
        serde_json::from_str(&serde_json::to_string(&psbt_base64).unwrap()).unwrap()
    }

    macro_rules! roundtrip {
        ($msg:ident) => {
            let serialized_msg = serde_json::to_string(&$msg).unwrap();
            let deserialized_msg = serde_json::from_str(&serialized_msg).unwrap();
            assert_eq!($msg, deserialized_msg);
            assert_eq!(
                serialized_msg,
                String::from_utf8_lossy(&serde_json::to_vec(&$msg).unwrap())
            );
        };
    }

    macro_rules! assert_str_ser {
        ($msg:ident, $str:expr) => {
            let ser = serde_json::to_string(&$msg).unwrap();
            assert_eq!(ser, $str);
        };
    }

    #[test]
    fn serde_watchtower_sig() {
        let pubkey: PublicKey = get_dummy_pubkey();
        let sig: Signature = get_dummy_sig();
        let emergency: BTreeMap<PublicKey, Signature> = [(pubkey, sig)].iter().cloned().collect();
        let cancel_sigs_20: BTreeMap<PublicKey, Signature> =
            [(pubkey, sig)].iter().cloned().collect();
        let cancel_sigs_100: BTreeMap<PublicKey, Signature> =
            [(pubkey, sig)].iter().cloned().collect();
        let cancel: BTreeMap<_, _> = [
            (
                watchtower::CancelFeerate(Amount::from_sat(20)),
                cancel_sigs_20,
            ),
            (
                watchtower::CancelFeerate(Amount::from_sat(100)),
                cancel_sigs_100,
            ),
        ]
        .iter()
        .cloned()
        .collect();
        let unvault_emergency: BTreeMap<PublicKey, Signature> =
            [(pubkey, sig)].iter().cloned().collect();
        let signatures = watchtower::Signatures {
            emergency,
            cancel,
            unvault_emergency,
        };
        let deposit_outpoint = OutPoint::from_str(
            "3694ef9e8fcd78e9b8165a41e6f5e2b5f10bcd92c6d6e42b3325a850df56cd83:0",
        )
        .unwrap();
        let derivation_index = 42398.into();
        let msg = watchtower::Sigs {
            signatures,
            deposit_outpoint,
            derivation_index,
        };
        let req = Request::from(msg);
        roundtrip!(req);
        assert_str_ser!(
            req,
            format!("{{\"method\":\"sigs\",\"params\":{{\"signatures\":{{\"emergency\":{{\"035be5e9478209674a96e60f1f037f6176540fd001fa1d64694770c56a7709c42c\":\"3045022100dc4dc264a9fef17a3f253449cf8c397ab6f16fb3d63d86940b5586823dfd02ae02203b461bb4336b5ecbaefd6627aa922efc048fec0c881c10c4c9428fca69c132a2\"}},\"cancel\":{{\"20\":{{\"035be5e9478209674a96e60f1f037f6176540fd001fa1d64694770c56a7709c42c\":\"3045022100dc4dc264a9fef17a3f253449cf8c397ab6f16fb3d63d86940b5586823dfd02ae02203b461bb4336b5ecbaefd6627aa922efc048fec0c881c10c4c9428fca69c132a2\"}},\"100\":{{\"035be5e9478209674a96e60f1f037f6176540fd001fa1d64694770c56a7709c42c\":\"3045022100dc4dc264a9fef17a3f253449cf8c397ab6f16fb3d63d86940b5586823dfd02ae02203b461bb4336b5ecbaefd6627aa922efc048fec0c881c10c4c9428fca69c132a2\"}}}},\"unvault_emergency\":{{\"035be5e9478209674a96e60f1f037f6176540fd001fa1d64694770c56a7709c42c\":\"3045022100dc4dc264a9fef17a3f253449cf8c397ab6f16fb3d63d86940b5586823dfd02ae02203b461bb4336b5ecbaefd6627aa922efc048fec0c881c10c4c9428fca69c132a2\"}}}},\"deposit_outpoint\":\"3694ef9e8fcd78e9b8165a41e6f5e2b5f10bcd92c6d6e42b3325a850df56cd83:0\",\"derivation_index\":42398}},\"id\":{}}}", req.id())
            );
    }

    #[test]
    fn serde_watchtower_sig_ack() {
        let ack = true;
        let msg = Response {
            result: ResponseResult::WtSigs(watchtower::SigsResult { ack }),
            id: 1946,
        };
        roundtrip!(msg);
        assert_str_ser!(msg, r#"{"result":{"ack":true},"id":1946}"#);
    }

    #[test]
    fn serde_watchtower_get_spend_tx() {
        let msg = coordinator::GetSpendTx {
            deposit_outpoint: OutPoint::from_str(
                "6a276a96807dd45ceed9cbd6fd48b5edf185623b23339a1643e19e8dcbf2e474:0",
            )
            .unwrap(),
        };
        let req = Request::from(msg);
        roundtrip!(req);
        assert_str_ser!(
            req,
            format!("{{\"method\":\"get_spend_tx\",\"params\":{{\"deposit_outpoint\":\"6a276a96807dd45ceed9cbd6fd48b5edf185623b23339a1643e19e8dcbf2e474:0\"}},\"id\":{}}}", req.id()
        ));

        // Response
        let msg = Response {
            result: ResponseResult::SpendTx(coordinator::SpendTx {
                transaction: Some(get_dummy_spend_tx().into_psbt().extract_tx()),
            }),
            id: 0,
        };
        roundtrip!(msg);
        assert_str_ser!(
            msg,
            r#"{"result":{"transaction":"AgAAAANJ71BuQ4CUtqlXOE1PYnawJZcyp7bHuDuSUSvc3r6nwAAAAAAABgAAAHDAIEqJqZwGfl+PShDdZwBT63AThd6ZwrgbaeWmuoEoAAAAAAAGAAAADAJghSHTLZuQgfwFVn96+4W6U4LE7Iav+u9mdHaT/1oAAAAAAAYAAAAEUKgAAAAAAAAiACC9fC/EFTZfTf6m5+zK0UnZ1LgEpVcgoxCbLFRdNs8k+YDw+gIAAAAAFgAUIwNcad58BvjztjF42OeltTMf6kRAS0wAAAAAABYAFP6urYtOj5ucCjdlCh5SDQXrFVlsjHcTAgAAAAAiACB8BhX++rPARYdLqRUyMDXJBFshCqr/+jubiKTR5JKVqwAAAAA="},"id":0}"#
        );

        // Response
        let msg = Response {
            result: ResponseResult::SpendTx(coordinator::SpendTx { transaction: None }),
            id: 0,
        };
        roundtrip!(msg);
        assert_str_ser!(msg, r#"{"result":{"transaction":null},"id":0}"#);
    }

    #[test]
    fn serde_server_sig() {
        let pubkey = get_dummy_pubkey();
        let signature = get_dummy_sig();
        let id = Txid::default();

        let msg = coordinator::Sig {
            pubkey,
            signature,
            id,
        };
        let req = Request::from(msg);
        roundtrip!(req);
        assert_str_ser!(
            req,
            format!("{{\"method\":\"sig\",\"params\":{{\"pubkey\":\"035be5e9478209674a96e60f1f037f6176540fd001fa1d64694770c56a7709c42c\",\"signature\":\"3045022100dc4dc264a9fef17a3f253449cf8c397ab6f16fb3d63d86940b5586823dfd02ae02203b461bb4336b5ecbaefd6627aa922efc048fec0c881c10c4c9428fca69c132a2\",\"id\":\"0000000000000000000000000000000000000000000000000000000000000000\"}},\"id\":{}}}", req.id()
        ));

        let resp = Response {
            result: ResponseResult::Sig(coordinator::SigResult { ack: true }),
            id: 0,
        };
        assert_str_ser!(resp, r#"{"result":{"ack":true},"id":0}"#);
        let resp = Response {
            result: ResponseResult::Sig(coordinator::SigResult { ack: false }),
            id: 988364,
        };
        assert_str_ser!(resp, r#"{"result":{"ack":false},"id":988364}"#);
    }

    #[test]
    fn serde_server_get_sigs() {
        let id = Txid::default();
        let msg = coordinator::GetSigs { id };
        let req = Request::from(msg);
        roundtrip!(req);
        assert_str_ser!(
            req,
            format!("{{\"method\":\"get_sigs\",\"params\":{{\"id\":\"0000000000000000000000000000000000000000000000000000000000000000\"}},\"id\":{}}}", req.id()
        ));
    }

    #[test]
    fn serde_server_sigs() {
        let pubkey: PublicKey = get_dummy_pubkey();
        let sig = get_dummy_sig();
        let signatures = [(pubkey, sig)].iter().cloned().collect();

        // With signatures
        let msg = Response {
            result: ResponseResult::Sigs(coordinator::Sigs { signatures }),
            id: 0,
        };
        roundtrip!(msg);
        assert_str_ser!(
            msg,
            r#"{"result":{"signatures":{"035be5e9478209674a96e60f1f037f6176540fd001fa1d64694770c56a7709c42c":"3045022100dc4dc264a9fef17a3f253449cf8c397ab6f16fb3d63d86940b5586823dfd02ae02203b461bb4336b5ecbaefd6627aa922efc048fec0c881c10c4c9428fca69c132a2"}},"id":0}"#
        );

        // Without signatures
        let signatures = BTreeMap::new();
        let msg = Response {
            result: ResponseResult::Sigs(coordinator::Sigs { signatures }),
            id: 2234,
        };
        roundtrip!(msg);
        assert_str_ser!(msg, r#"{"result":{"signatures":{}},"id":2234}"#);
    }

    #[test]
    fn serde_server_request_spend() {
        let secp_ctx = Secp256k1::verification_only();
        let deposit_outpoints = vec![OutPoint::from_str(
            "6e4977728e7100db80c30751f27cf834b7a1e02d083a4338874e48d1f3694446:0",
        )
        .unwrap()];
        let mut signed_spend_tx = SpendTransaction::from_psbt_str("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").unwrap();
        signed_spend_tx.finalize(&secp_ctx).unwrap();
        let msg = coordinator::SetSpendTx::from_spend_tx(deposit_outpoints, signed_spend_tx);
        let req = Request::from(msg);
        roundtrip!(req);
        assert_str_ser!(
            req,
            format!("{{\"method\":\"set_spend_tx\",\"params\":{{\"deposit_outpoints\":[\"6e4977728e7100db80c30751f27cf834b7a1e02d083a4338874e48d1f3694446:0\"],\"transaction\":\"AgAAAAABA0nvUG5DgJS2qVc4TU9idrAllzKntse4O5JRK9zevqfAAAAAAAAGAAAAcMAgSompnAZ+X49KEN1nAFPrcBOF3pnCuBtp5aa6gSgAAAAAAAYAAAAMAmCFIdMtm5CB/AVWf3r7hbpTgsTshq/672Z0dpP/WgAAAAAABgAAAARQqAAAAAAAACIAIL18L8QVNl9N/qbn7MrRSdnUuASlVyCjEJssVF02zyT5gPD6AgAAAAAWABQjA1xp3nwG+PO2MXjY56W1Mx/qREBLTAAAAAAAFgAU/q6ti06Pm5wKN2UKHlINBesVWWyMdxMCAAAAACIAIHwGFf76s8BFh0upFTIwNckEWyEKqv/6O5uIpNHkkpWrBABHMEQCIFLZr2Nuwobsgymjcn58PicDmbhIDxSVijJweBKGAo33AiBc/NsJUNa39emKW0Dqn4LxaHtdhKnLE2dh7vy1IUCjJwFIMEUCIQD2i3eZIuOtA77TH878EP5qNijM4lUXSxCGcB+yW05mFQIgeDNpJ78R91RZYJYnCSSKnt8i4fg5Ts1FYzOElL0vrYIBwVIhAzVqDuAgpaArpeXgi3dflyz8T+CzCLFMvlzNNcJZufcCIQKkN7RngHjATz0dun59JLi9AktAMm6w5bvDcCMxTjrpMyECaAQSMA1k18IzLHtjIgfP5CHBTmQAogA3JmZbYhJfOTdTrmR2qRSHvfw0TjWTqeTgEOkQqyA3JQgxI4isa3apFCbNhNu0kGIW4eMsTZDvpQ5xaggmiKxsk2t2qRQbXA/bi900SbdbgiI9ifFG+GI74IisbJNTh2dWsmgEAEgwRQIhAJnsrYnLPsa6MsrNXiBSX2ot8xheYZ3T4TAwS+zzFqX4AiA2Fae4gOxRaDD5lG/F2vIJ3tZgzW9YmOQD3FISjKPorQFHMEQCIA60INngILKViBvvKfTfg2TqNizWnCDbHNJTWJpoDSfpAiBuPKDnZmKJZWvs4UHJSFvz02D8+maPaT/JEhhPdixr/wHBUiECBI1AhZI2dhKt8SXyO7NMrD2jcGNhD4OBvKLNKGorMhwhA361G3JukjFUr0h3DGxPEWDLZiyJCq2ca+ejBd6U9uUmIQLblte6cEoOmasC9eIFsn/7H06jmkv7wWEqACpdJ6yfRVOuZHapFNZYZNebVTETiuqoPYWSIpL3ivxhiKxrdqkUIG96fbB3lAIWgcCX+JEeD71ImSCIrGyTa3apFE/+YTc56xM7qRIk6CwECjItN87yiKxsk1OHZ1ayaAQASDBFAiEAqz2O8jH95Dcdg1e7NbqZBKmDIrHqmG+NZE3Sd8gRC8sCIHruGPZ4xm2gnH+JjFnTVyOEfbPC+8H8SfsT1tRLnGaVAUcwRAIgB4sc2wYN/EZoBxzi9tRVZU6XxwP4RDLr8cj8Iy3ADlACIFdNttmXUsFtttvOHnCpo+r5turWYdrQwGwXl1Wg27U+AcFSIQIEjUCFkjZ2Eq3xJfI7s0ysPaNwY2EPg4G8os0oaisyHCEDfrUbcm6SMVSvSHcMbE8RYMtmLIkKrZxr56MF3pT25SYhAtuW17pwSg6ZqwL14gWyf/sfTqOaS/vBYSoAKl0nrJ9FU65kdqkU1lhk15tVMROK6qg9hZIikveK/GGIrGt2qRQgb3p9sHeUAhaBwJf4kR4PvUiZIIisbJNrdqkUT/5hNznrEzupEiToLAQKMi03zvKIrGyTU4dnVrJoAAAAAA==\"}},\"id\":{}}}", req.id()
        ));

        let response = Response {
            result: ResponseResult::SetSpend(coordinator::SetSpendResult { ack: true }),
            id: 0,
        };
        assert_str_ser!(response, r#"{"result":{"ack":true},"id":0}"#);
        let response = Response {
            result: ResponseResult::SetSpend(coordinator::SetSpendResult { ack: false }),
            id: u32::MAX,
        };
        assert_str_ser!(response, r#"{"result":{"ack":false},"id":4294967295}"#);
    }

    #[test]
    fn serde_cosigner_sign() {
        let tx = get_dummy_spend_tx();
        let msg = cosigner::SignRequest { tx };
        let req = Request::from(msg);
        roundtrip!(req);
        assert_str_ser!(
            req,
            format!("{{\"method\":\"sign\",\"params\":{{\"tx\":\"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\"}},\"id\":{}}}", req.id()
        ));

        let msg = Response {
            result: ResponseResult::SignResult(cosigner::SignResult { tx: None }),
            id: 975687,
        };
        roundtrip!(msg);
        assert_str_ser!(msg, r#"{"result":{"tx":null},"id":975687}"#);

        // Deserializing a Spend transaction with no sighash field in input
        let ser_params = "{\"tx\":\"cHNidP8BAH0CAAAAAUDRi/I+wdCXYqm+b0ZNC0JJ4kPOjjWgyqfDqkRkWr1jAAAAAAAMAAAAAuBNAAAAAAAAIgAghXb+XrrWUcewRGtvvKkI02ZqC4NYBeDzQLHStslIam0QcEsAAAAAABYAFHUJaO12ZJ6K2STXEKCQKQ5JfAd2AAAAAAABASt2wUsAAAAAACIAIJ9anuC7OiZJ3VMaM4rUoHH8a6BN/lud5132EqTrZdz4AQX9KgFTIQLIhDMNnqMPsx/QZTsg/cO1SD93/VqCp9hXALtGlLcnWSEDFVkeCrrXp810ESIUJ8lUwxb/eH9C18ptQhYgbH0n/84hAuCqv0zFH2ZeyCQh933cb5+hXvlf9JfkTNxQS2qqlF3JU65kdqkU/qKS/zB0mmVtjUmFgIBPWvBAyvmIrGt2qRQi5fmveMZXYHT/ram4mvaongbir4isbJNrdqkU38PCnD1R2c4KZVqRZB29tl/aEAyIrGyTU4dnUyEDu6dc/zIdd3TF2Xi3OvVCrS2H0EdOOAlJ8gEJOj1a+sUhAhiqwCZJU/81M2TigtYtpJT8HYykIZEq3SRXgqOr1hFBIQLZsWpwpnrYsFxMRLTxsbZC3Kb3ppYlNdb/vrO9NplP+VOvXLJoIgYCGKrAJklT/zUzZOKC1i2klPwdjKQhkSrdJFeCo6vWEUEIAAAAAAAAAAAiBgLIhDMNnqMPsx/QZTsg/cO1SD93/VqCp9hXALtGlLcnWQhkO24IAAAAACIGAtmxanCmetiwXExEtPGxtkLcpvemliU11v++s702mU/5CAAAAAAAAAAAIgYC4Kq/TMUfZl7IJCH3fdxvn6Fe+V/0l+RM3FBLaqqUXckIGKgaewAAAAAiBgMIodGQzuUg9ZxB9kTks8tA8ZA6i6HFD/0LVtCsGQKkgQgbkrTHAAAAACIGAxVZHgq616fNdBEiFCfJVMMW/3h/QtfKbUIWIGx9J//OCP8WLnkAAAAAIgYDUtEj1nQPFzpDqGiEAu9czBoarP1BaJwTGTEzCjgIIu8IrPnB6gAAAAAiBgO7p1z/Mh13dMXZeLc69UKtLYfQR044CUnyAQk6PVr6xQgAAAAAAAAAACIGA/kcSpLFKYjr50DiECQ9rJmhTpqSGVL53bXiKuna2nb5CN7LraIAAAAAACICAxsyFTyoUli+Yxo7c3Ul6xOjmR3O+IAUbCjMutTnjcmSCNKOGewAAAAAIgIDZD+iYCgAyKT+IN3SuAX6Rub0G5bv9vBqLYbAN13jAkgIN21tegAAAAAiAgPQrxUb9g0nWoCNoUwKCXKkHrfjif0UvWN/ieGbnWP/3Ahlt8UZAAAAAAAA\"}";
        serde_json::from_str::<cosigner::SignRequest>(&ser_params).unwrap();
        let ser_req = "{\"method\":\"sign\",\"params\":{\"tx\":\"cHNidP8BAH0CAAAAAUDRi/I+wdCXYqm+b0ZNC0JJ4kPOjjWgyqfDqkRkWr1jAAAAAAAMAAAAAuBNAAAAAAAAIgAghXb+XrrWUcewRGtvvKkI02ZqC4NYBeDzQLHStslIam0QcEsAAAAAABYAFHUJaO12ZJ6K2STXEKCQKQ5JfAd2AAAAAAABASt2wUsAAAAAACIAIJ9anuC7OiZJ3VMaM4rUoHH8a6BN/lud5132EqTrZdz4AQX9KgFTIQLIhDMNnqMPsx/QZTsg/cO1SD93/VqCp9hXALtGlLcnWSEDFVkeCrrXp810ESIUJ8lUwxb/eH9C18ptQhYgbH0n/84hAuCqv0zFH2ZeyCQh933cb5+hXvlf9JfkTNxQS2qqlF3JU65kdqkU/qKS/zB0mmVtjUmFgIBPWvBAyvmIrGt2qRQi5fmveMZXYHT/ram4mvaongbir4isbJNrdqkU38PCnD1R2c4KZVqRZB29tl/aEAyIrGyTU4dnUyEDu6dc/zIdd3TF2Xi3OvVCrS2H0EdOOAlJ8gEJOj1a+sUhAhiqwCZJU/81M2TigtYtpJT8HYykIZEq3SRXgqOr1hFBIQLZsWpwpnrYsFxMRLTxsbZC3Kb3ppYlNdb/vrO9NplP+VOvXLJoIgYCGKrAJklT/zUzZOKC1i2klPwdjKQhkSrdJFeCo6vWEUEIAAAAAAAAAAAiBgLIhDMNnqMPsx/QZTsg/cO1SD93/VqCp9hXALtGlLcnWQhkO24IAAAAACIGAtmxanCmetiwXExEtPGxtkLcpvemliU11v++s702mU/5CAAAAAAAAAAAIgYC4Kq/TMUfZl7IJCH3fdxvn6Fe+V/0l+RM3FBLaqqUXckIGKgaewAAAAAiBgMIodGQzuUg9ZxB9kTks8tA8ZA6i6HFD/0LVtCsGQKkgQgbkrTHAAAAACIGAxVZHgq616fNdBEiFCfJVMMW/3h/QtfKbUIWIGx9J//OCP8WLnkAAAAAIgYDUtEj1nQPFzpDqGiEAu9czBoarP1BaJwTGTEzCjgIIu8IrPnB6gAAAAAiBgO7p1z/Mh13dMXZeLc69UKtLYfQR044CUnyAQk6PVr6xQgAAAAAAAAAACIGA/kcSpLFKYjr50DiECQ9rJmhTpqSGVL53bXiKuna2nb5CN7LraIAAAAAACICAxsyFTyoUli+Yxo7c3Ul6xOjmR3O+IAUbCjMutTnjcmSCNKOGewAAAAAIgIDZD+iYCgAyKT+IN3SuAX6Rub0G5bv9vBqLYbAN13jAkgIN21tegAAAAAiAgPQrxUb9g0nWoCNoUwKCXKkHrfjif0UvWN/ieGbnWP/3Ahlt8UZAAAAAAAA\"},\"id\":2670297491}";
        serde_json::from_str::<Request>(&ser_req).unwrap();
    }
}
