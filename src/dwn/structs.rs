use super::Error;

use super::permission::{Permission};

use crate::common::traits::Indexable;
use crate::common::database::{IndexBuilder, Index};
use crate::common::structs::DateTime;

use crate::crypto::secp256k1::{SecretKey, PublicKey};
use crate::crypto::traits::{Hashable};
use crate::crypto::structs::Hash;

use crate::dids::structs::Did;
use crate::dids::signing::SignedObject;

use schemars::JsonSchema;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Record {
    pub record_id: Hash,
    pub protocol: Hash,
    pub payload: Vec<u8>,
    pub channel_deletes: Vec<usize>
}

impl Record {
    pub fn new(record_id: Option<Hash>, protocol: Hash, payload: Vec<u8>) -> Self {
        Record{record_id: record_id.unwrap_or(payload.hash()), protocol, payload, channel_deletes: Vec::new()}
    }
    pub fn get_latest_delete(&self) -> usize {
        self.channel_deletes.iter().max_by_key(|i| *i).copied().unwrap_or_default()
    }
}

impl Hashable for Record {}
impl Indexable for Record {}

pub type PermissionedRecord = (Permission, Record);

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
pub enum Action{Create, Read, Update, Delete}

pub type CreateRequest = DwnItem;
pub type ReadRequest = SignedObject<String>;//Discover signed Optional Delete
pub type UpdateRequest = SignedObject<DwnItem>;
pub type DeleteRequest = SignedObject<PublicKey>;//Delete Signed Some(Discover)
pub type CreateDMRequest = DwnItem;
pub type ReadDMRequest = SignedObject<DateTime>;

pub struct RequestBuilder {}
impl RequestBuilder {
    pub fn create(
        create: &SecretKey,
        perm_record: PermissionedRecord,
    ) -> Result<CreateRequest, Error> {
        let perms = &perm_record.0;
        let discover = perms.discover.public_key();
        if create.public_key() != perms.create.map_ref_to_left(|k| k.public_key()) {
            return Err(Error::bad_request("RequestBuilder.create", "Create does not match"));
        }
        let read = perms.read.map_ref_to_left(|k| k.public_key());
        let delete = perms.delete.as_ref().map(|d| d.map_ref_to_left(|k| k.public_key()));
        let signed = SignedObject::from_key(create, perm_record)?;
        let payload = read.encrypt(&serde_json::to_vec(&signed)?)?;
        Ok(DwnItem::new(discover, delete, payload))
    }

    pub fn read(discover: &SecretKey) -> Result<ReadRequest, Error> {
        SignedObject::from_key(discover, String::new())
    }

    pub fn update(
        create: &SecretKey,
        delete: &SecretKey,
        pr: PermissionedRecord
    ) -> Result<UpdateRequest, Error> {
        let error = || Error::bad_request("RequestBuilder.update", "Delete key does not match");
        if delete.public_key() != pr.0.delete.as_ref().ok_or(error())?.map_ref_to_left(|k| k.public_key()) {
            return Err(error());
        }
        let create_request = Self::create(create, pr)?;
        SignedObject::from_key(delete, create_request)
    }

    pub fn delete(delete: &SecretKey, discover: PublicKey) -> Result<DeleteRequest, Error> {
        SignedObject::from_key(delete, discover)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DwnRequest {
    pub dm: bool,
    pub action: Action,//Create, Read, Update, Delete
    pub payload: Vec<u8>,
}

impl DwnRequest {
    pub fn new(dm: bool, action: Action, payload: Vec<u8>) -> Self {
        DwnRequest{dm, action, payload}
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
