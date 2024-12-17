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

use std::collections::{VecDeque, BTreeMap};
use std::sync::Arc;

use simple_crypto::{Hashable, SecretKey, PublicKey, Key};
use simple_database::database::{Filters, SortOptions};

use serde::{Serializer, Serialize, Deserialize};
use schemars::JsonSchema;
use uuid::Uuid;
use rand::Fill;

use super::traits::TypeDebug;

const INDEX_UUID: Uuid = Uuid::max();

pub type Protocols<'a> = &'a BTreeMap<Uuid, Protocol>;
pub type BoxCallback<'a> = Box<dyn FnOnce(Responses) -> BoxCommand<'a> + 'a + Send + Sync>;
pub type BoxCommand<'a> = Box<dyn Command<'a> + 'a>;
pub type Tasks<'a> = Vec<(Uuid, Task<'a>)>;
pub type RecordInfo = (Protocol, PermissionSet);
pub type Responses = Vec<Box<dyn Response>>;
pub type BoxResponse = Box<dyn Response>;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Header(pub Uuid, pub Endpoint);

#[derive(JsonSchema, Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct RecordPath {
    inner: Vec<Uuid>
}

impl RecordPath {
    pub fn new(path: &[Uuid]) -> Self {
        RecordPath{inner: path.to_vec()}
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
    //Read(PermissionSet, Signer),
}

impl AgentRequest {
    pub fn into_dwn_request(self) -> Result<DwnRequest, Error> {
        Ok(match self {
            Self::ReadPrivate(discover) =>
                DwnRequest::ReadPrivate(SignedObject::from_key(&discover, String::new())?),
            Self::ReadPublic(filters, sort_options) =>
                DwnRequest::ReadPublic(filters, sort_options),
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
        protocol: &Protocol,
        payload: Vec<u8>
    ) -> Result<Self, Error> {
        protocol.validate_payload(&payload)?;
        let discover = perms.discover();
        let create = perms.create()?;
        let subset_perms = protocol.subset_permission(perms, p_opts)?;
        let pr = PrivateRecord::new(subset_perms, protocol.uuid(), payload);
        Ok(Self::CreatePrivate(Box::new(pr), discover, create))
    }

    pub fn create_private_child(
        parent_perms: &PermissionSet,
        child_perms: &PermissionSet,
        index: usize
    ) -> Result<Self, Error> {
        let protocol = SystemProtocols::perm_pointer();
        let perms = parent_perms.pointer(index)?;
        let discover = perms.discover();
        let create = perms.create()?;
        let subset = protocol.subset_permission(perms, None)?;
        let pr = PrivateRecord::new(subset, protocol.uuid(), serde_json::to_vec(&child_perms)?);
        Ok(Self::CreatePrivate(Box::new(pr), discover, create))
    }

    pub fn update_private(
        perms: PermissionSet,
        p_opts: Option<&PermissionOptions>,
        protocol: &Protocol,
        payload: Vec<u8>
    ) -> Result<Self, Error> {
        let delete = perms.delete()?;
        let req = Self::create_private(perms, p_opts, protocol, payload)?;
        if let Self::CreatePrivate(pr, discover, create) = req {
            Ok(Self::UpdatePrivate(pr, discover, create, delete))
        } else {panic!("Impossible");}
    }

    pub fn update_index(perms: PermissionSet, index: usize) -> Result<Self, Error> {
        Self::update_private(perms, None, &SystemProtocols::usize(), serde_json::to_vec(&index)?)
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

pub enum Task<'a> {
    Ready(Header, BoxCommand<'a>),
    Waiting(Header, BoxCallback<'a>, Vec<Uuid>),
    Request(Header, AgentRequest),
    MutableRequest(Header, MutableAgentRequest, usize),
    Completed(BoxResponse),
}

impl<'a> Task<'a> {
    pub fn ready(header: Header, command: (impl Command<'a> + 'a)) -> Task<'a> {
        Task::Ready(header, Box::new(command))
    }

    pub fn next(uuid: Uuid, header: Header, command: (impl Command<'a> + 'a)) -> Result<Tasks<'a>, Error> {
        Ok(vec![(uuid, Task::ready(header, command))])
    }

    pub fn waiting(
        uuid: Uuid, header: Header, callback: BoxCallback<'a>, tasks: Vec<Task<'a>>
    ) -> Result<Tasks<'a>, Error> {
        let mut tasks = tasks.into_iter().map(|task| {
            (Uuid::new_v4(), task)
        }).collect::<VecDeque<_>>();
        let ids = tasks.iter().map(|(id,_)| *id).collect::<Vec<_>>();
        tasks.push_front((uuid, Task::Waiting(header, Box::new(callback), ids)));
        Ok(tasks.into())
    }
    pub fn completed(uuid: Uuid, response: impl Response) -> Result<Tasks<'a>, Error> {
        Ok(vec![(uuid, Task::Completed(Box::new(response)))])
    }
}

pub struct Callback {}
impl Callback {
    #[allow(clippy::new_ret_no_self)]
    pub fn new<'a, T: Command<'a> + 'a>(command: impl FnOnce(Responses) -> T + 'a + Send + Sync) -> BoxCallback<'a> {
        let callback = move |results: Responses| -> BoxCommand {Box::new(command(results))};
        Box::new(callback)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub path: RecordPath,
    pub protocol: Uuid,
    pub payload: Vec<u8>
}

impl Record {
    pub fn new(path: RecordPath, protocol: Uuid, payload: &[u8]) -> Self {
        Record{path, protocol, payload: payload.to_vec()}
    }
}

impl std::fmt::Debug for PrivateRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.payload)
    }
}

#[derive(JsonSchema, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PrivateRecord {
    pub perms: PermissionSet,
    pub protocol: Uuid,
    pub payload: Vec<u8>
}

impl PrivateRecord {
    pub fn new(perms: PermissionSet, protocol: Uuid, payload: Vec<u8>) -> Self {
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

#[derive(Clone, Debug)]
pub struct ErrorWrapper {
    pub inner: Arc<Error>
}

impl ErrorWrapper {
    pub fn new(error: Error) -> Self {
        ErrorWrapper{inner: Arc::new(error)}
    }
}

impl Serialize for ErrorWrapper {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut buffer: [u8; 32] = [0; 32];
        buffer.try_fill(&mut rand::thread_rng()).unwrap();
        serializer.serialize_bytes(&buffer)
    }
}
