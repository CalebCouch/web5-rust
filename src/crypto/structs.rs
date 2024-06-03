use super::Error;

use crate::common::structs::Schemas;

use bitcoin_hashes::sha256::Hash as BHash;
pub use bitcoin_hashes::Hash as _;
use schemars::gen::SchemaGenerator;
use schemars::schema::Schema;
use schemars::JsonSchema;

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[derive(serde_with::SerializeDisplay)]
#[derive(serde_with::DeserializeFromStr)]
pub struct Hash {
    inner: BHash
}

impl Hash {
    pub fn all_zeros() -> Self {Hash{inner: BHash::all_zeros()}}
    pub fn new(inner: BHash) -> Self {Hash{inner}}
    pub fn to_vec(&self) -> Vec<u8> {
        self.inner.as_byte_array().to_vec()
    }
    pub fn as_bytes(&self) -> &[u8] {self.inner.as_byte_array()}
    pub fn from_slice(slice: &[u8]) -> Result<Self, Error> {
        Ok(Hash{inner: BHash::from_slice(slice)?})
    }
}

impl std::fmt::Display for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.to_vec()))
    }
}

impl std::str::FromStr for Hash {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Hash::from_slice(&hex::decode(s)?)
    }
}

impl JsonSchema for Hash {
    fn schema_name() -> String {"Hash".to_string()}
    fn json_schema(_gen: &mut SchemaGenerator) -> Schema {
        Schemas::regex("^(0x|0X)?[a-fA-F0-9]{64}$".to_string())
    }
}
