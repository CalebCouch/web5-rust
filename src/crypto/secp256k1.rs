use super::Error;

use super::structs::Hash;

use crate::common::structs::{Schemas, Either};

use bitcoin_hashes::{Hash as BHash, hash160, sha256};
use serde::{Serialize, Deserialize};
use schemars::gen::SchemaGenerator;
use secp256k1::schnorr::Signature;
use secp256k1::{Message, Keypair};
use bitcoin::NetworkKind;
use bitcoin::bip32::{
    ChildNumber,
    Xpriv,
};
use schemars::schema::Schema;
use schemars::JsonSchema;

fn message(payload: &[u8]) -> Message {
    //Tagged hash: see taproot rust bitcoin
    Message::from_digest(*sha256::Hash::hash(payload).as_ref())
}

pub type Key = Either<PublicKey, SecretKey>;

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PublicKey {
    key: secp256k1::PublicKey
}

impl PublicKey {
    pub fn to_vec(&self) -> Vec<u8> {
        self.key.serialize().to_vec()
    }
    pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        Ok(PublicKey{key: secp256k1::PublicKey::from_slice(b)?})
    }
    pub fn thumbprint(&self) -> String {
        hex::encode(hash160::Hash::hash(&self.key.serialize()))
    }

    pub fn verify(&self, payload: &[u8], signature: &[u8]) -> Result<(), Error> {
        Ok(Signature::from_slice(signature)?.verify(
            &message(payload),
            &self.key.x_only_public_key().0
        )?)
    }

    pub fn encrypt(&self, payload: &[u8]) -> Result<Vec<u8>, Error> {
        ecies::encrypt(&self.to_vec(), payload).map_err(
            |_| Error::err("PublicKey::encrypt", "failed to encrypt")
        )
    }
}

impl JsonSchema for PublicKey {
    fn schema_name() -> String {"PublicKey".to_string()}
    fn json_schema(_gen: &mut SchemaGenerator) -> Schema {
        Schemas::regex("^(0x|0X)?[a-fA-F0-9]{32}$".to_string())
    }
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.to_vec()))
    }
}

#[derive(Clone, PartialEq, Eq)]
#[derive(serde_with::SerializeDisplay)]
#[derive(serde_with::DeserializeFromStr)]
pub struct SecretKey {
    key: secp256k1::SecretKey
}

impl SecretKey {
    pub fn new() -> Self {
        SecretKey{
            key: secp256k1::SecretKey::new(&mut secp256k1::rand::thread_rng())
        }
    }
    pub fn encrypt_self(&self, public_key: &PublicKey) -> Result<Vec<u8>, Error> {
        public_key.encrypt(&serde_json::to_vec(&self.key)?)
    }
    pub fn sign(&self, payload: &[u8]) -> Vec<u8> {
        Keypair::from_secret_key(
            &secp256k1::Secp256k1::new(),
            &self.key
        ).sign_schnorr(message(payload)).serialize().to_vec()
    }
    pub fn decrypt(&self, payload: &[u8]) -> Result<Vec<u8>, Error> {
        ecies::decrypt(&self.key.secret_bytes(), payload).map_err(
            |_| Error::err("SecretKey.decrypt", "failed to decrypt")
        )
    }
    pub fn public_key(&self) -> PublicKey {
        PublicKey{key: self.key.public_key(&secp256k1::Secp256k1::new())}
    }

    pub fn derive_usize(&self, index: usize) -> Result<Self, Error> {
        self.get_child(Derivation::from_usize(index)?)
    }

    pub fn derive_hash(&self, hash: &Hash) -> Result<Self, Error> {
        self.get_child(Derivation::from_hash(hash)?)
    }

    pub fn get_child(&self, derivation_path: Vec<ChildNumber>) -> Result<Self, Error> {
        let x_priv = Xpriv::new_master(
            NetworkKind::Main,
            &self.key.secret_bytes()
        )?;
        Ok(SecretKey{
            key: x_priv.derive_priv(
                &secp256k1::Secp256k1::new(),
                &derivation_path,
            )?.to_priv().inner
        })
    }
}

impl Default for SecretKey {
    fn default() -> Self {Self::new()}
}

impl Ord for SecretKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.key.secret_bytes().cmp(&other.key.secret_bytes())
    }
}


impl PartialOrd for SecretKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretKey")
        .field("key", &&self.to_string()[0..10])
        .field("kp", &&self.public_key().to_string()[0..10])
//      .field("create", &&self.derive_usize(0).unwrap().to_string()[0..6])
//      .field("cp", &&self.derive_usize(0).unwrap().public_key().to_string()[0..6])
//      .field("discover", &&self.derive_usize(1).unwrap().to_string()[0..6])
//      .field("dip", &&self.derive_usize(1).unwrap().public_key().to_string()[0..6])
//      .field("rp", &&self.derive_usize(2).unwrap().public_key().to_string()[0..6])
//      .field("delete", &&self.derive_usize(3).unwrap().to_string()[0..6])
//      .field("dep", &&self.derive_usize(3).unwrap().public_key().to_string()[0..6])
//      .field("CC", &&self.derive_usize(4).unwrap().to_string()[0..6])
//      .field("CCp", &&self.derive_usize(4).unwrap().public_key().to_string()[0..6])
//      .field("DC", &&self.derive_usize(5).unwrap().to_string()[0..6])
//      .field("DCp", &&self.derive_usize(5).unwrap().public_key().to_string()[0..6])
//      .field("RC", &&self.derive_usize(6).unwrap().to_string()[0..6])
//      .field("RCp", &&self.derive_usize(6).unwrap().public_key().to_string()[0..6])
        .finish()

    }
}

impl std::fmt::Display for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.key.secret_bytes()))
    }
}

impl std::str::FromStr for SecretKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(SecretKey{key: secp256k1::SecretKey::from_slice(&hex::decode(s)?)?})
    }
}

impl JsonSchema for SecretKey {
    fn schema_name() -> String {"SecretKey".to_string()}
    fn json_schema(_gen: &mut SchemaGenerator) -> Schema {
        Schemas::regex("^(0x|0X)?[a-fA-F0-9]{64}$".to_string())
    }
}

pub struct Derivation {}
impl Derivation {
    pub fn from_bytes(bytes: &[u8]) -> Result<Vec<ChildNumber>, Error> {
        let mut results = vec![];
        for i in 0..(bytes.len()/3)+1 {
            let index = u32::from_le_bytes([
                bytes.get(i).copied().unwrap_or_default(),
                bytes.get(i+1).copied().unwrap_or_default(),
                bytes.get(i+2).copied().unwrap_or_default(),
                0
            ]);
            results.push(ChildNumber::from_hardened_idx(index)?);
        }
        Ok(results)
    }
    pub fn from_usize(index: usize) -> Result<Vec<ChildNumber>, Error> {
        Self::from_bytes(&index.to_le_bytes())
    }
    pub fn from_hash(hash: &Hash) -> Result<Vec<ChildNumber>, Error> {
        Self::from_bytes(hash.as_bytes())
    }
}
