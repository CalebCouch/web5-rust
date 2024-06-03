use super::Error;

use std::str::FromStr;
use std::fmt;

use bitcoin_hashes::{Hash as _, sha256};

use schemars::schema::{Schema, SchemaObject, StringValidation};
use schemars::{JsonSchema, Map};
use schemars::gen::SchemaGenerator;
use serde_json::value::Value;


#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[derive(serde_with::SerializeDisplay)]
#[derive(serde_with::DeserializeFromStr)]
pub struct Hash {
    inner: sha256::Hash
}

impl Hash {
    pub fn hash(content: &[u8]) -> Cid {
        Hash{inner: sha256::Hash::hash(content)}
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.hash.borrow().to_vec()
    }
    pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        Ok(Cid{cid: cid::Cid::from_str(std::str::from_utf8(b)?)?})
    }
}

impl fmt::Display for Cid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.inner.borrow()))
    }
}

impl std::fmt::Debug for Cid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}...", &self.hash.to_string()[..10])
    }
}


impl std::str::FromStr for Cid {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Hash{cid: cid::Cid::from_str(s)?})
    }
}

impl JsonSchema for Cid {
    fn schema_name() -> String {"Cid".to_string()}

    fn json_schema(_gen: &mut SchemaGenerator) -> Schema {
        Schema::Object(
            SchemaObject{
                metadata: None,
                instance_type: None,
                format: None,
                enum_values: None,
                const_value: None,
                subschemas: None,
                number: None,
                string: Some(Box::new(StringValidation {
                    max_length: None,
                    min_length: None,
                    pattern: None
                })),
                array: None,
                object: None,
                reference: None,
                extensions: Map::<String, Value>::new()
            }
        )
    }
}
