use super::Error;

use crate::dids::signing::{SignedObject, Signer};
use crate::dids::{DidResolver, Did};

use simple_crypto::{Hashable, SecretKey, PublicKey};
use simple_database::database::{IndexBuilder, Index, Filters, SortOptions};
use simple_database::Indexable;

use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;

//TODO: Fix circular dependency
use crate::agent::Protocol;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub enum DwnResponse {
    ReadPrivate(Option<DwnItem>),
    ReadPublic(Vec<PublicDwnItem>),
    ReadDM(Vec<DwnItem>),
    InvalidAuth(String),
    PublicConflict(PublicDwnItem),
    Conflict(DwnItem),
    #[default]
    Empty,
}

impl DwnResponse {
    pub fn is_invalid_auth(&self) -> bool {
        matches!(self, Self::InvalidAuth(_))
    }

    pub fn into_read_private(self) -> Result<Option<DwnItem>, Error> {
        match self {
            Self::ReadPrivate(pr) => Ok(pr),
            other => Err(Error::bad_response(&format!("Expected ReadPrivate(_) Got {:?}", other)))
        }
    }

    pub fn into_invalid_auth(self) -> Result<String, Error> {
        match self {
            Self::InvalidAuth(i) => Ok(i),
            other => Err(Error::bad_response(&format!("Expected InvalidAuth(_) Got {:?}", other)))
        }
    }

    pub fn into_empty(self) -> Result<(), Error> {
        match self {
            Self::Empty => Ok(()),
            other => Err(Error::bad_response(&format!("Expected Empty Got {:?}", other)))
        }
    }

    pub fn into_conflict(self) -> Result<DwnItem, Error> {
        match self {
            Self::Conflict(item) => Ok(item),
            other => Err(Error::bad_response(&format!("Expected Conflict(_) Got {:?}", other)))
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Packet {
    pub recipient: Did,
    pub payload: Vec<u8>
}

impl Packet {
    pub async fn new(
        did_resolver: &dyn DidResolver, recipient: Did, payload: &[u8]
    ) -> Result<Self, Error> {
        let (_, key) = did_resolver.resolve_dwn_keys(&recipient).await?;
        Ok(Packet{
            recipient,
            payload: key.encrypt(payload)?
        })
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DwnItem {
    pub discover: PublicKey,
    pub delete: Option<PublicKey>,
    pub payload: Vec<u8>
}

impl Hashable for DwnItem {}
impl Indexable for DwnItem {
    const PRIMARY_KEY: &'static str = "discover";
    fn primary_key(&self) -> Vec<u8> {self.discover.to_vec()}
    fn secondary_keys(&self) -> Index {
        IndexBuilder::build(vec![
            ("delete", self.delete.as_ref().map(|d| d.to_vec()).unwrap_or_default())
        ]).unwrap()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PublicRecord {
    pub uuid: Uuid,
    pub protocol: Protocol,
    pub payload: Vec<u8>,
    pub index: Index,
}

impl PublicRecord {
    pub fn new(uuid: Option<Uuid>, protocol: Protocol, payload: &[u8], index: Option<Index>) -> Result<Self, Error> {
        let uuid = uuid.unwrap_or(Uuid::new_v4());
        let index = index.unwrap_or_default();
        if index.contains_key("signer") ||
           index.contains_key("protocol") ||
           index.contains_key("payload") ||
           index.contains_key("uuid") {
            Err(Error::bad_request("'signer', 'protocol', 'payload', and 'uuid' are reserved indexes"))
        } else {Ok(PublicRecord{uuid, protocol, payload: payload.to_vec(), index})}
    }

    pub fn into_item(self, signer: Signer) -> Result<PublicDwnItem, Error> {
        Ok(PublicDwnItem(SignedObject::new(signer, self)?))
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PublicDwnItem(pub SignedObject<PublicRecord>);

impl Hashable for PublicDwnItem {}
impl Indexable for PublicDwnItem {
    const PRIMARY_KEY: &'static str = "uuid";
    fn primary_key(&self) -> Vec<u8> {self.0.inner().uuid.as_bytes().to_vec()}
    fn secondary_keys(&self) -> Index {
        let mut index = IndexBuilder::build(vec![
            ("signer", self.0.signer().to_string()),
            ("protocol", self.0.inner().protocol.uuid().to_string()),
            ("payload", self.0.inner().payload.hash().to_string()),
        ]).unwrap();
        index.extend(self.0.inner().index.clone());
        index
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum DwnRequest{
    CreatePrivate(SignedObject<DwnItem>),
    ReadPrivate(SignedObject<String>),
    UpdatePrivate(SignedObject<SignedObject<DwnItem>>),
    DeletePrivate(SignedObject<PublicKey>),//Delete Signed Some(Discover)

    CreatePublic(PublicDwnItem),
    ReadPublic(Filters, Option<SortOptions>),
    UpdatePublic(PublicDwnItem),
    DeletePublic(SignedObject<Uuid>),

    CreateDM(DwnItem),
    ReadDM(SignedObject<DateTime<Utc>>)
}

impl DwnRequest {
    pub fn read_private(discover: &SecretKey) -> Result<DwnRequest, Error> {
        let payload = SignedObject::from_key(discover, String::new())?;
        Ok(DwnRequest::ReadPrivate(payload))
    }

    pub fn delete_private(discover: PublicKey, delete: &SecretKey) -> Result<DwnRequest, Error> {
        let payload = SignedObject::from_key(delete, discover)?;
        Ok(DwnRequest::DeletePrivate(payload))
    }
}
