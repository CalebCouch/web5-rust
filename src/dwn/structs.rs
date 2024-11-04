use super::Error;

use super::permission::{PermissionSet};
use super::protocol::{SystemProtocols, Protocol};

use chrono::{DateTime, Utc};

use simple_crypto::{SecretKey, PublicKey, Hashable, Hash};

use crate::dids::signing::{Signer, SignedObject};
use crate::dids::{DidKeyPair, Did};

use jsonschema::JSONSchema;
use schemars::JsonSchema;
use serde::{Serialize, Deserialize};

use std::collections::BTreeMap;

use simple_database::database::{IndexBuilder, Index, Filters, SortOptions};
use simple_database::Indexable;


#[derive(JsonSchema, Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Record {
    pub record_id: Hash,
    pub protocol: Hash,
    pub payload: Vec<u8>,
}

impl Record {
    pub fn new(record_id: Option<Hash>, protocol: Hash, payload: Vec<u8>) -> Self {
        Record{record_id: record_id.unwrap_or(payload.hash()), protocol, payload}
    }

    pub fn validate(&self, protocol: &Protocol) -> Result<(), Error> {
        let error = |r: &str| Error::bad_request("Protocol.validate_payload", r);
        if let Some(schema) = protocol.schema.as_ref() {
            JSONSchema::compile(&serde_json::from_str(schema)?)
            .map_err(|e| error(&format!("schema failed to compile: {:?}", e)))?
            .validate(&serde_json::from_slice(&self.payload)?)
            .map_err(|e| error(&format!(
                "schema failed for payload: {:?}",
                e.map(|e| e.to_string()).collect::<Vec<String>>()
            )))?;
        } else if !self.payload.is_empty() {
            return Err(error("Payload was not empty"));
        }
        Ok(())
    }
}

impl Hashable for Record {}
impl Indexable for Record {
    fn primary_key(&self) -> Vec<u8> {self.hash_bytes()}
}

#[derive(JsonSchema, Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PermissionedRecord{
    pub perms: PermissionSet,
    pub record: Record
}

impl PermissionedRecord {
    pub fn new(
        perms: PermissionSet,
        record: Record
    ) -> Self {
        PermissionedRecord{perms, record}
    }

    pub fn is_valid_child(&self, protocol: &Protocol) -> Result<(), Error> {
        protocol.is_valid_child(&self.record.protocol)
    }

    pub fn validate(&self, protocol: &Protocol) -> Result<(), Error> {
        let error = |r: &str| Error::bad_request("Protocol.validate", r);

        if protocol.hash() != self.record.protocol {
            return Err(error("Record does not use this protocol"));
        }

        let trimmed = self.perms.clone().trim(protocol);
        if self.perms != trimmed {
            return Err(error("Permission contained a delete key or channel keys which are unsupported by this protocol"));
        }
        trimmed.get_min_perms(protocol).or(Err(error(
            "Permission could not meet minimum permission requirements"
        )))?;

        self.record.validate(protocol)?;
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, PartialOrd, Eq, Ord)]
pub struct PublicRecord {
    pub inner: SignedObject<(Record, Index)>,
}

impl PublicRecord {
    pub fn new(signer: Signer, record: Record, index: Index) -> Result<Self, Error> {
        Ok(PublicRecord{inner: SignedObject::new(signer, (record, index))?})
    }
}

impl Hashable for PublicRecord {}
impl Indexable for PublicRecord {
    fn primary_key(&self) -> Vec<u8> {self.inner.inner().0.record_id.to_vec()}
    fn secondary_keys(&self) -> Index {
        let mut indexes = self.inner.inner().1.clone();
        indexes.insert("author".to_string(), self.inner.signer().to_string().into());
        indexes.insert("protocol".to_string(), self.inner.inner().0.protocol.to_vec().into());
        indexes.insert("payload_hash".to_string(), self.inner.inner().0.payload.hash().to_vec().into());
        indexes
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Packet {
    pub recipient: Did,
    pub payload: Vec<u8>
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DwnItem {
    pub discover: PublicKey,
    pub delete: Option<PublicKey>,
    pub payload: Vec<u8>
}

impl DwnItem {
    pub fn new(discover: PublicKey, delete: Option<PublicKey>, payload: Vec<u8>) -> Self {
        DwnItem{discover, delete, payload}
    }
}

impl Hashable for DwnItem {}

impl Indexable for DwnItem {
    const PRIMARY_KEY: &'static str = "discover";
    fn primary_key(&self) -> Vec<u8> {
        self.discover.to_vec()
    }
    fn secondary_keys(&self) -> Index {
        let mut ib = IndexBuilder::new();
        ib.add("delete", self.delete.as_ref().map(|d| d.to_vec()).unwrap_or_default());
        ib.finish()
    }
}

#[derive(JsonSchema, Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Type{DM, Private, Public}

#[derive(JsonSchema, Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Action{Create, Read, Update, Delete}

pub type PrivateCreateRequest = DwnItem;
pub type PrivateReadRequest = SignedObject<String>;//Discover signed Optional Delete
pub type PrivateUpdateRequest = SignedObject<DwnItem>;
pub type PrivateDeleteRequest = SignedObject<PublicKey>;//Delete Signed Some(Discover)

pub type PublicCreateRequest = PublicRecord;
pub type PublicReadRequest = (Filters, Option<SortOptions>);
pub type PublicUpdateRequest = PublicRecord;
pub type PublicDeleteRequest = SignedObject<Hash>;

pub type DMCreateRequest = DwnItem;
pub type DMReadRequest = SignedObject<DateTime<Utc>>;


#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DwnRequest {
    pub r#type: Type,
    pub action: Action,
    pub payload: Vec<u8>,
}

impl DwnRequest {
    pub fn new(r#type: Type, action: Action, payload: Vec<u8>) -> Self {
        DwnRequest{r#type, action, payload}
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Status {
    pub code: u32,
    pub detail: String
}

#[derive(Serialize, Deserialize, Clone)]
pub struct DwnResponse {
    pub status: Status,
    pub payload: Option<Vec<u8>>
}

impl DwnResponse {
    pub fn new(code: u32, detail: &str, payload: Option<Vec<u8>>) -> Self {
        DwnResponse{status: Status{code, detail: detail.to_string()}, payload}
    }

    pub fn handle(self, allow_forwarding: bool) -> Result<Option<Vec<u8>>, Error> {
        match &self.status.code {
            400 => Err(Error::bad_request("", &self.status.detail)),
            401 => Err(Error::auth_failed("", &self.status.detail)),
            404 => Err(Error::not_found("", &self.status.detail)),
            409 => Err(Error::conflict("", &self.status.detail)),
            500 => Err(Error::err("", &self.status.detail)),
            303 if !allow_forwarding => Err(Error::err("500/303", "unexpected forward")),
            _ => Ok(self.payload),
        }
    }
}

impl From<Error> for DwnResponse {
    fn from(item: Error) -> Self {
        match item {
            Error::BadRequest(ctx, err) => DwnResponse::new(400, &Error::BadRequest(ctx, err).to_string(), None),
            Error::AuthFailed(ctx, err) => DwnResponse::new(401, &Error::AuthFailed(ctx, err).to_string(), None),
            Error::NotFound(ctx, err) => DwnResponse::new(404, &Error::NotFound(ctx, err).to_string(), None),
            Error::Conflict(ctx, err) => DwnResponse::new(409, &Error::Conflict(ctx, err).to_string(), None),
            other => DwnResponse::new(500, &other.to_string(), None)
        }
    }
}

impl std::fmt::Debug for DwnResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DwnResponse")
        .field("status", &self.status)
        .finish()
    }
}

#[derive(JsonSchema, Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DwnKey {
    pub key: SecretKey,
    pub path: Vec<Hash>
}

impl DwnKey {
    pub fn new(key: SecretKey, path: Vec<Hash>) -> Self {
        DwnKey{key, path}
    }

    pub fn new_root(key: SecretKey) -> Self {
        DwnKey{key, path: vec![]}
    }

    pub fn derive_path(&self, path: &[Hash]) -> Result<Self, Error> {
        if let Some(striped_path) = path.strip_prefix(self.path.as_slice()) {
            let mut key = self.key.clone();
            for hash in striped_path {
                key = key.derive_hash(hash)?;
            }
            Ok(DwnKey::new(key, path.to_owned()))
        } else {Err(Error::InsufficentPermission())}
    }
}

#[derive(JsonSchema, Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProtocolFetcher {
    pub sys: BTreeMap<Hash, Protocol>,
    pub other: BTreeMap<Hash, Protocol>
}

impl ProtocolFetcher {
    pub fn new(others: Vec<Protocol>) -> Self {
        let other = BTreeMap::from_iter(others.into_iter().map(|p| (p.hash(), p)));
        ProtocolFetcher{sys: SystemProtocols::get_map(), other}
    }

    pub fn get(&self, protocol: &Hash) -> Result<&Protocol, Error> {
        if let Some(sys_p) = self.sys.get(protocol) {return Ok(sys_p);}
        self.other.get(protocol).ok_or(Error::bad_request("Client.get_protocol", "Protocol not configured"))
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct AgentKey {
    pub sig_key: DidKeyPair,
    pub enc_key: DwnKey,
    pub com_key: DwnKey,
    pub master_protocol: Hash,
}

impl AgentKey {
    pub fn new(
        sig_key: DidKeyPair,
        enc_key: DwnKey,
        com_key: DwnKey,
        master_protocol: Hash,
    ) -> Self {
        AgentKey{sig_key, enc_key, com_key, master_protocol}
    }
}
