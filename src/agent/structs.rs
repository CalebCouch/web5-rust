use super::Error;

use super::permission::{
    ChannelPermissionSet,
    PermissionOptions,
    PermissionSet
};
use super::protocol::{SystemProtocols, Protocol};
use super::traits::{Response, Command};

use crate::dids::signing::{SignedObject, Signer};
use crate::dids::Endpoint;

use crate::dwn::structs::{DwnRequest, DwnItem, PublicRecord};

use std::collections::{VecDeque};

use simple_crypto::{Hashable, SecretKey, PublicKey, Key};
use simple_database::database::{Filters, SortOptions};

use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use uuid::Uuid;

use super::traits::TypeDebug;

const INDEX_UUID: Uuid = Uuid::max();

pub type BoxCallback = Box<dyn FnOnce(Responses) -> BoxCommand + Send + Sync>;
pub type BoxCommand = Box<dyn Command>;
pub type Tasks = Vec<(Uuid, Task)>;
pub type RecordInfo = (Protocol, PermissionSet);
pub type Responses = Vec<Box<dyn Response>>;
pub type BoxResponse = Box<dyn Response>;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Header {
    pub oid: Uuid,
    pub endpoint: Endpoint,
    pub order: usize,
    pub enc: bool
}

//TODO: impl eq to check everything but order and oid

impl Header {
    pub fn new(oid: Uuid, endpoint: Endpoint, order: usize, enc: bool) -> Self {
        Header{oid, endpoint, order, enc}
    }
    pub fn com(&self) -> Self {
        let mut header = self.clone();
        header.enc = false;
        header
    }
}

#[derive(JsonSchema, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Default)]
#[derive(serde_with::SerializeDisplay)]
#[derive(serde_with::DeserializeFromStr)]
pub struct RecordPath {
    inner: Vec<Uuid>
}

impl std::fmt::Display for RecordPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "/{}", self.inner.iter().map(|id| id.to_string()).collect::<Vec<_>>().join("/"))
    }
}

impl std::str::FromStr for RecordPath {
    type Err = uuid::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(RecordPath{inner:
            s[1..].split("/").collect::<Vec<_>>()
            .into_iter().filter_map(|id|
                if id.is_empty() {None} else {Some(Uuid::from_str(id))}
            ).collect::<Result<Vec<Uuid>, uuid::Error>>()?
        })
    }
}

impl RecordPath {
    pub fn new(path: &[Uuid]) -> Self {
        RecordPath{inner: path.to_vec()}
    }

    pub fn parent_of(&self, path: &RecordPath) -> bool {
        path.as_slice().strip_prefix(self.as_slice()).is_some()
    }

    pub fn root() -> Self {
        RecordPath{inner: Vec::new()}
    }

    pub fn last(&self) -> Uuid {
        self.inner.last().copied().unwrap_or(Uuid::nil())
    }

    pub fn is_empty(&self) -> bool {self.inner.is_empty()}

    pub fn as_slice(&self) -> &[Uuid] {
        self.inner.as_slice()
    }

    pub fn parent(&self) -> Result<Self, Error> {
        match self.inner.split_last() {
            Some(p) => Ok(RecordPath::new(p.1)),
            None => {Err(Error::bad_request("Cannot Get Parent Of Root"))}
        }
    }

    pub fn index(&self) -> Self {
        self.extend(&[INDEX_UUID])
    }

    pub fn extend(&self, path: &[Uuid]) -> Self {
        RecordPath::new(&[&self.inner, path].concat())
    }
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub enum AgentRequest {
    ReadPrivate(SecretKey),
    ReadPublic(Filters, Option<SortOptions>),
    ReadDM(DateTime<Utc>, Signer),
}

impl AgentRequest {
    pub fn into_dwn_request(self) -> Result<DwnRequest, Error> {
        Ok(match self {
            Self::ReadPrivate(discover) =>
                DwnRequest::ReadPrivate(SignedObject::from_key(&discover, String::new())?),
            Self::ReadPublic(filters, sort_options) =>
                DwnRequest::ReadPublic(filters, sort_options),
            Self::ReadDM(timestamp, signer) =>
                DwnRequest::ReadDM(SignedObject::new(signer, timestamp)?),
        })
    }
}

impl Hashable for AgentRequest {}

#[derive(Serialize, Clone, PartialEq, Eq)]
pub enum MutableAgentRequest {
    CreatePrivate(Box<PrivateRecord>, SecretKey, SecretKey),
    UpdatePrivate(Box<PrivateRecord>, SecretKey, SecretKey, SecretKey),
    DeletePrivate(PublicKey, SecretKey),

    CreatePublic(Box<PublicRecord>, Signer),
    UpdatePublic(Box<PublicRecord>, Signer),
    DeletePublic(Uuid, Signer),

    CreateDM(Box<PermissionSet>, Signer, PublicKey),
}

impl std::fmt::Debug for MutableAgentRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let id = self.get_id();
        match self {
            Self::CreatePrivate(p,_,_) => write!(f, "CreatePrivate({}, {:?})", id, p.payload.truncate_debug(20)),
            Self::UpdatePrivate(p,_,_,_) => write!(f, "UpdatePrivate({}, {:?})", id, p.payload.truncate_debug(20)),
            Self::DeletePrivate(_,_) => write!(f, "DeletePrivate({})", id),
            Self::CreatePublic(r,_) => write!(f, "CreatePublic({}, {:?})", id, r.payload.truncate_debug(20)),
            Self::UpdatePublic(r,_) => write!(f, "UpdatePublic({}, {:?})", id, r.payload.truncate_debug(20)),
            Self::DeletePublic(_,_) => write!(f, "DeletePublic({})", id),
            Self::CreateDM(_,_,_) => write!(f, "CreateDM({})", id),
        }
    }
}


impl Hashable for MutableAgentRequest {}

impl MutableAgentRequest {
    pub fn get_id(&self) -> Uuid {
        match self {
            Self::CreatePrivate(_,d,_) => Uuid::new_v5(&Uuid::NAMESPACE_OID, &d.public_key().to_vec()),
            Self::UpdatePrivate(_,d,_,_) => Uuid::new_v5(&Uuid::NAMESPACE_OID, &d.public_key().to_vec()),
            Self::DeletePrivate(d,_) => Uuid::new_v5(&Uuid::NAMESPACE_OID, &d.to_vec()),
            Self::CreatePublic(r,_) => r.uuid,
            Self::UpdatePublic(r,_) => r.uuid,
            Self::DeletePublic(u,_) => *u,
            Self::CreateDM(_,_,_) => Uuid::new_v4()
        }
    }

    fn create_request(
        record: PrivateRecord, discover: &SecretKey, create: SecretKey
    ) -> Result<SignedObject<DwnItem>, Error> {
        SignedObject::from_key(discover, record.into_item(Some(&create))?)
    }

    fn create_dm_request(
        signer: Signer, com_key: PublicKey, perms: PermissionSet
    ) -> Result<DwnItem, Error> {
        let payload = com_key.encrypt(&serde_json::to_vec(&SignedObject::new(signer, perms)?)?)?;
        Ok(DwnItem{discover: com_key, delete: None, payload})
    }

    pub fn into_dwn_request(self) -> Result<DwnRequest, Error> {
        Ok(match self {
            Self::CreatePrivate(record, discover, create) =>
                DwnRequest::CreatePrivate(Self::create_request(*record, &discover, create)?),
            Self::UpdatePrivate(record, discover, create, delete) =>
                DwnRequest::UpdatePrivate(SignedObject::from_key(
                    &delete, Self::create_request(*record, &discover, create)?
                )?),
            Self::DeletePrivate(discover, delete) =>
                DwnRequest::DeletePrivate(SignedObject::from_key(&delete, discover)?),
            Self::CreatePublic(record, signer) =>
                DwnRequest::CreatePublic(record.into_item(signer)?),
            Self::UpdatePublic(record, signer) =>
                DwnRequest::UpdatePublic(record.into_item(signer)?),
            Self::DeletePublic(uuid, signer) =>
                DwnRequest::DeletePublic(SignedObject::new(signer, uuid)?),
            Self::CreateDM(perms, signer, com_key) =>
                DwnRequest::CreateDM(Self::create_dm_request(signer, com_key, *perms)?)
        })
    }

    pub fn create_private(
        perms: PermissionSet,
        p_opts: Option<&PermissionOptions>,
        protocol: Protocol,
        payload: Vec<u8>
    ) -> Result<Self, Error> {
        protocol.validate_payload(&payload)?;
        let discover = perms.discover();
        let create = perms.create()?;
        let subset_perms = protocol.subset_permission(perms, p_opts)?;
        let pr = PrivateRecord::new(subset_perms, protocol, payload);
        Ok(Self::CreatePrivate(Box::new(pr), discover, create))
    }

    pub fn create_private_child(
        parent_perms: &PermissionSet,
        child_perms: &PermissionSet,
        index: usize
    ) -> Result<Self, Error> {
        let perms = parent_perms.pointer(index)?;
        let discover = perms.discover();
        let create = perms.create()?;
        let protocol = SystemProtocols::perm_pointer();
        let subset = protocol.subset_permission(perms, None)?;
        let pr = PrivateRecord::new(subset, protocol, serde_json::to_vec(&child_perms)?);
        Ok(Self::CreatePrivate(Box::new(pr), discover, create))
    }

    pub fn update_private(
        perms: PermissionSet,
        p_opts: Option<&PermissionOptions>,
        protocol: Protocol,
        payload: Vec<u8>
    ) -> Result<Self, Error> {
        let delete = perms.delete()?;
        let req = Self::create_private(perms, p_opts, protocol, payload)?;
        if let Self::CreatePrivate(pr, discover, create) = req {
            Ok(Self::UpdatePrivate(pr, discover, create, delete))
        } else {panic!("Impossible");}
    }

    pub fn update_index(perms: PermissionSet, index: usize) -> Result<Self, Error> {
        Self::update_private(perms, None, SystemProtocols::usize(), serde_json::to_vec(&index)?)
    }

    pub fn delete_private(perms: &PermissionSet) -> Result<Self, Error> {
        Ok(Self::DeletePrivate(perms.discover.public_key(), perms.delete()?))
    }

    pub fn create_public(
        record: PublicRecord, signer: Signer
    ) -> Result<Self, Error> {
        Ok(Self::CreatePublic(Box::new(record), signer))
    }

    pub fn update_public(
        record: PublicRecord, signer: Signer
    ) -> Result<Self, Error> {
        Ok(Self::UpdatePublic(Box::new(record), signer))
    }

    pub fn delete_public(uuid: Uuid, signer: Signer) -> Result<Self, Error> {
        Ok(Self::DeletePublic(uuid, signer))
    }

    pub fn create_dm(
        perms: PermissionSet, signer: Signer, com_key: PublicKey
    ) -> Result<Self, Error> {
        Ok(Self::CreateDM(Box::new(perms), signer, com_key))
    }
}

pub enum Task {
    Ready(Header, BoxCommand),
    Waiting(Header, BoxCallback, Vec<Uuid>),
    Request(Header, AgentRequest),
    MutableRequest(Header, MutableAgentRequest, usize),
    Completed(BoxResponse),
}

impl Task {
    pub fn ready(header: Header, command: (impl Command + 'static)) -> Task {
        Task::Ready(header, Box::new(command))
    }

    pub fn next(uuid: Uuid, header: Header, command: (impl Command + 'static)) -> Result<Tasks, Error> {
        Ok(vec![(uuid, Task::ready(header, command))])
    }

    pub fn waiting(
        uuid: Uuid, header: Header, callback: BoxCallback, tasks: Vec<Task>
    ) -> Result<Tasks, Error> {
        let mut tasks = tasks.into_iter().map(|task| {
            (Uuid::new_v4(), task)
        }).collect::<VecDeque<_>>();
        let ids = tasks.iter().map(|(id,_)| *id).collect::<Vec<_>>();
        tasks.push_front((uuid, Task::Waiting(header, Box::new(callback), ids)));
        Ok(tasks.into())
    }
  //pub fn complete(response: impl Response) -> Result<Tasks, Error> {
  //    Task::Completed(Box::new(response))
  //}
    pub fn completed(uuid: Uuid, response: impl Response) -> Result<Tasks, Error> {
        Ok(vec![(uuid, Task::Completed(Box::new(response)))])
    }
}

pub struct Callback {}
impl Callback {
    #[allow(clippy::new_ret_no_self)]
    pub fn new<T: Command + 'static>(callback: impl FnOnce(Responses) -> T + Send + Sync + 'static) -> BoxCallback {
        let callback = move |results: Responses| -> BoxCommand {Box::new(callback(results))};
        Box::new(callback)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub path: RecordPath,
    pub protocol: Protocol,
    pub payload: Vec<u8>
}

impl Record {
    pub fn new(path: RecordPath, protocol: Protocol, payload: &[u8]) -> Self {
        Record{path, protocol, payload: payload.to_vec()}
    }
}

impl Hashable for Record {}

impl std::fmt::Debug for PrivateRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.payload)
    }
}

#[derive(JsonSchema, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PrivateRecord {
    pub perms: PermissionSet,
    pub protocol: Protocol,
    pub payload: Vec<u8>
}

impl PrivateRecord {
    pub fn new(perms: PermissionSet, protocol: Protocol, payload: Vec<u8>) -> Self {
        PrivateRecord{perms, protocol, payload}
    }

    pub fn into_record(self) -> Record {
        Record{path: self.perms.path, protocol: self.protocol, payload: self.payload}
    }

    pub fn into_item(self, create: Option<&SecretKey>) -> Result<DwnItem, Error> {
        let discover = self.perms.discover.public_key();
        let delete = self.perms.delete.clone().map(|d| d.public_key());
        let read = self.perms.read.public_key();
        let create = match create {
            Some(create) => {
                if create.public_key() != self.perms.create.public_key() {
                    return Err(Error::invalid_auth("Create"));
                }
                create
            },
            None => &self.perms.create.secret_key().ok_or(Error::invalid_auth("Create"))?
        };
        let signed = SignedObject::from_key(create, self)?;
        let payload = read.encrypt(&serde_json::to_vec(&signed)?)?;

        Ok(DwnItem{discover, delete, payload})
    }
}

#[derive(JsonSchema, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PathedKey {
    pub key: SecretKey,
    pub path: RecordPath
}

impl PathedKey {
    pub fn new(key: SecretKey, path: RecordPath) -> Self {
        PathedKey{key, path}
    }

    pub fn new_root(key: SecretKey) -> Self {
        PathedKey{key, path: RecordPath::new(&[])}
    }

    pub fn derive_path(&self, path: &[Uuid]) -> Result<Self, Error> {
        if let Some(striped_path) = path.strip_prefix(self.path.as_slice()) {
            let mut key = self.key.clone();
            for uuid in striped_path {
                key = key.derive_bytes(uuid.as_bytes())?;
            }
            Ok(PathedKey::new(key, RecordPath::new(path)))
        } else {Err(Error::insufficent_permission())}
    }

    pub fn to_permission(&self) -> Result<PermissionSet, Error> {
        let path = self.path.clone();
        let key = &self.key;
        Ok(PermissionSet::new(
            path,
            key.derive_usize(0)?,
            Key::new_secret(key.derive_usize(1)?),
            Key::new_secret(key.derive_usize(2)?),
            Some(Key::new_secret(key.derive_usize(3)?)),
            Some(ChannelPermissionSet::new(
                Key::new_secret(key.derive_usize(4)?),
                Key::new_secret(key.derive_usize(5)?),
                Key::new_secret(key.derive_usize(6)?),
            ))
        ))
    }

    pub fn get_perms(&self, path: &RecordPath, protocol: Option<&Protocol>) -> Result<PermissionSet, Error> {
        self.get_perms_from_slice(path.as_slice(), protocol)
    }

    pub fn get_perms_from_slice(&self, path: &[Uuid], protocol: Option<&Protocol>) -> Result<PermissionSet, Error> {
        let perms = self.derive_path(path)?.to_permission()?;
        if let Some(protocol) = protocol {
            Ok(protocol.trim_permission(perms))
        } else {Ok(perms)}
    }
}
