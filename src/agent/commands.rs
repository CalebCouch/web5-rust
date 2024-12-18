use super::Error;

use super::compiler::{CompilerMemory, CompilerCache};
use super::permission::{PermissionOptions, PermissionSet};
use super::protocol::{SystemProtocols, Protocol};
use super::traits::Command;
use super::structs::{
    MutableAgentRequest,
    PrivateRecord,
    AgentRequest,
    RecordPath,
    RecordInfo,
    Responses,
    Callback,
    Header,
    Record,
    Tasks,
    Task,
};

use crate::dids::signing::{SignedObject, Signer};
use crate::dids::{DidResolver, Endpoint, Did};
use crate::dwn::structs::DwnResponse;

use simple_crypto::SecretKey;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct EnsureEmpty {
    responses: Responses
}

impl EnsureEmpty {
    pub fn new(responses: Responses) -> Self {
        EnsureEmpty{responses}
    }
}

#[async_trait::async_trait]
impl<'a> Command<'a> for EnsureEmpty {
    async fn process(
        self: Box<Self>, uuid: Uuid, _: Header,
        _: &mut CompilerMemory<'a>, _: &mut CompilerCache
    ) -> Result<Tasks<'a>, Error> {
        for response in self.responses {
            if response.downcast_ref::<()>().is_some() {} else {
                (*response.downcast::<DwnResponse>()?).into_empty()?;
            }
        }
        Task::completed(uuid, ())
    }
}

#[derive(Debug, Clone)]
pub struct CreatePrivate {}
impl CreatePrivate {
    pub fn create(
        header: Header, memory: &mut CompilerMemory, cache: &mut CompilerCache,
        record: Record, p_opts: Option<&PermissionOptions>
    ) -> Result<(PermissionSet, MutableAgentRequest), Error> {
        let protocol = memory.get_protocol(&record.protocol)?.clone();
        let perms = memory.key.get_perms(&record.path, Some(&protocol))?;
        let min_perms = protocol.subset_permission(perms.clone(), None)?;
        let req = MutableAgentRequest::create_private(perms.clone(), p_opts, &protocol, record.payload)?;

        cache.record_info.insert((header.1, record.path.clone()), (protocol, perms));

        Ok((min_perms, req))
    }

    pub fn create_child(
        header: Header, memory: &mut CompilerMemory,
        parent_perms: &PermissionSet, child_perms: &PermissionSet, index: usize
    ) -> Result<(MutableAgentRequest, MutableAgentRequest, usize), Error> {
        let index_key = (header.1, parent_perms.path.clone());
        let index = memory.create_index.get(&index_key).copied().unwrap_or(index);
        memory.create_index.insert(index_key, index+1);

        let index_perms = memory.key.get_perms(&parent_perms.path.index(), None)?;
        let index_req = MutableAgentRequest::update_index(index_perms, index+1)?;
        let child_req = MutableAgentRequest::create_private_child(parent_perms, child_perms, index)?;
        Ok((index_req, child_req, index+1))
    }
}

#[derive(Debug, Clone)]
pub enum ReadPrivate {
    #[allow(non_camel_case_types)]
    child(RecordPath, usize),
    ChildInfo(Responses, usize),
    ChildComplete(Responses, Protocol),
    #[allow(non_camel_case_types)]
    path(RecordPath),
    #[allow(non_camel_case_types)]
    new(Box<PermissionSet>, bool),
    Complete(Responses, Box<PermissionSet>, bool, bool),
}

impl ReadPrivate {
    fn read_private(
        perms: &PermissionSet, memory: &CompilerMemory, response: &DwnResponse
    ) -> Result<(Option<PrivateRecord>, bool), Error> {
        let discover = perms.discover.public_key();
        let create = perms.create.public_key();
        let read = perms.read.secret_key().ok_or(Error::invalid_auth("Read"))?;

        if let DwnResponse::ReadPrivate(item) = response {
            if let Some(item) = item {
                let dc = read.decrypt(&item.payload)?;
                let signed = serde_json::from_slice::<SignedObject<PrivateRecord>>(&dc)?;
                let mut record = signed.verify_with_key(&create)?;
                let protocol = memory.get_protocol(&record.protocol)?;
                let perms = protocol.trim_permission(perms.clone());
                let delete = perms.delete.as_ref().map(|d| d.public_key());
                perms.validate(&record.perms)?;
                protocol.validate_payload(&record.payload)?;
                protocol.validate_permission(&record.perms)?;
                if item.discover != discover || item.delete != delete {
                    return Err(Error::bad_response("Internal and External Key Mismatch"));
                }
                record.perms = record.perms.combine(perms)?;
                Ok((Some(record), true))
            } else {Ok((None, false))}
        } else {Err(Error::bad_response(&format!("Expected ReadPrivate(_) got {:?}", response)))}
    }
}

#[async_trait::async_trait]
impl<'a> Command<'a> for ReadPrivate {
    async fn process(
        self: Box<Self>, uuid: Uuid, header: Header,
        memory: &mut CompilerMemory<'a>, cache: &mut CompilerCache
    ) -> Result<Tasks<'a>, Error> {
        match *self {
            Self::child(parent_path, index) => {
                let callback = move |r: Responses| {Self::ChildInfo(r, index)};
                Task::waiting(uuid, header.clone(), Callback::new(callback), vec![
                    Task::ready(header, ReadInfo::new(parent_path, PermissionOptions::read_child()))
                ])
            },
            Self::ChildInfo(mut responses, index) => {
                let info = *responses.remove(0).downcast::<RecordInfo>()?;
                let perms = info.1.pointer(index)?;
                let callback = move |r: Responses| {Self::ChildComplete(r, info.0)};
                Task::waiting(uuid, header.clone(), Callback::new(callback), vec![
                    Task::ready(header, Self::new(Box::new(perms), true))
                ])
            },
            Self::ChildComplete(mut r, parent_protocol) => {
                let mut child = *r.remove(0).downcast::<(Option<Box<PrivateRecord>>, bool)>()?;
                child.0.as_mut().filter(|c| parent_protocol.validate_child(&c.protocol).is_ok());
                Task::completed(uuid, child)
            },
            Self::path(path) => {
                if path.is_empty() {
                    let protocol = SystemProtocols::root();
                    Task::completed(uuid, (Some(Box::new(
                        PrivateRecord::new(memory.key.get_perms_from_slice(&[], Some(&protocol))?, protocol.uuid(), Vec::new())
                    )), true))
                } else {
                    let perms = memory.key.get_perms(&path, None)?;
                    Task::next(uuid, header, Self::new(Box::new(perms), true))
                }
            },
            Self::new(perms, resolve) => {
                let req = AgentRequest::ReadPrivate(perms.discover());
                let callback = move |r: Responses| {Self::Complete(r, Box::new(*perms), resolve, false)};
                Task::waiting(uuid, header.clone(), Callback::new(callback), vec![
                    Task::Request(header, req)
                ])
            }
            Self::Complete(mut results, perms, resolve, exists) => {
                let res = results.remove(0).downcast::<DwnResponse>()?;
                let record = if let Ok((record, nexists)) = Self::read_private(&perms, memory, &res) {
                    let exists = exists || nexists;
                    if let Some(record) = record {
                        if resolve && record.protocol == SystemProtocols::perm_pointer().uuid() {
                            let perms: PermissionSet = serde_json::from_slice(&record.payload)?;
                            let req = AgentRequest::ReadPrivate(perms.discover());
                            let callback = move |r: Responses| {Self::Complete(r, Box::new(perms), false, exists)};
                            return Task::waiting(uuid, header.clone(), Callback::new(callback), vec![
                                Task::Request(header, req)
                            ]);
                        }
                        if let Ok(protocol) = memory.get_protocol(&record.protocol) {
                            cache.record_info.insert(
                                (header.1.clone(), perms.path.clone()),
                                (protocol.clone(), record.perms.clone())
                            );
                        }
                        (Some(Box::new(record)), exists)
                    } else {(None, exists)}
                } else {(None, exists)};
                Task::completed(uuid, record)
            },
        }
    }
}

#[derive(Debug, Clone)]
pub enum ReadInfo {
    #[allow(non_camel_case_types)]
    new(RecordPath, PermissionOptions),
    Complete(Responses)
}

#[async_trait::async_trait]
impl<'a> Command<'a> for ReadInfo {
    async fn process(
        self: Box<Self>, uuid: Uuid, header: Header,
        memory: &mut CompilerMemory<'a>, cache: &mut CompilerCache
    ) -> Result<Tasks<'a>, Error> {
        match *self {
            Self::new(path, p_opts) => {
                match cache.record_info.get(&(header.1.clone(), path.clone())) {
                    Some(info) if info.clone().1.subset(&p_opts).is_ok() => {
                        Task::completed(uuid, info.clone())
                    },
                    _ => {
                        Task::waiting(uuid, header.clone(), Callback::new(Self::Complete), vec![
                            Task::ready(header, ReadPrivate::path(path))
                        ])
                    }
                }
            }
            Self::Complete(mut results) => {
                let record = results.remove(0).downcast::<(Option<Box<PrivateRecord>>, bool)>()?.0;
                if let Some(record) = record {
                    Task::completed(uuid, (memory.get_protocol(&record.protocol)?.clone(), record.perms))
                } else {Err(Error::not_found("Record information"))}
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct ReadParent {
    path: RecordPath,
}

impl ReadParent {
    pub fn new(path: RecordPath) -> Self {
        ReadParent{path}
    }
}

#[async_trait::async_trait]
impl<'a> Command<'a> for ReadParent {
    async fn process(
        self: Box<Self>, uuid: Uuid, header: Header,
        memory: &mut CompilerMemory<'a>, _: &mut CompilerCache
    ) -> Result<Tasks<'a>, Error> {
        let parent_path = self.path.parent()?;
        if parent_path.is_empty() {
            let protocol = SystemProtocols::root();
            Task::completed(uuid, Some(Box::new(
                PrivateRecord::new(memory.key.get_perms_from_slice(&[], Some(&protocol))?, protocol.uuid(), Vec::new())
            )))
        } else {
            let perms = memory.key.get_perms(&parent_path, None)?;
            Task::next(uuid, header, ReadPrivate::new(Box::new(perms), true))
        }
    }
}

#[derive(Debug, Clone)]
pub struct NextIndex {
    discover_child: SecretKey,
    index: usize,
    results: Option<Responses>,
}

impl NextIndex {
    pub fn new(
        discover_child: SecretKey,
        index: usize,
        results: Option<Responses>,
    ) -> Self {
        NextIndex{discover_child, index, results}
    }
}

#[async_trait::async_trait]
impl<'a> Command<'a> for NextIndex {
    async fn process(
        self: Box<Self>, uuid: Uuid, header: Header,
        _: &mut CompilerMemory<'a>, _: &mut CompilerCache
    ) -> Result<Tasks<'a>, Error> {
        let discover_child = self.discover_child;
        let mut index = self.index;
        if let Some(mut results) = self.results {
            if *results.remove(0).downcast::<bool>()? {
                index += 1;
            } else {
                return Task::completed(uuid, index);
            }
        }
        let discover = discover_child.derive_usize(self.index)?;
        let callback = move |r: Responses| {NextIndex::new(discover_child, index, Some(r))};
        Task::waiting(uuid, header.clone(), Callback::new(callback), vec![
            Task::Ready(header, Box::new(Exists::new(discover)))
        ])
    }
}

#[derive(Debug, Clone)]
pub enum Exists {
    #[allow(non_camel_case_types)]
    path(RecordPath),
    #[allow(non_camel_case_types)]
    new(SecretKey),
    Complete(Responses),
}

#[async_trait::async_trait]
impl<'a> Command<'a> for Exists {
    async fn process(
        self: Box<Self>, uuid: Uuid, header: Header,
        memory: &mut CompilerMemory<'a>, _: &mut CompilerCache
    ) -> Result<Tasks<'a>, Error> {
        match *self {
            Self::path(path) => {
                let discover = memory.key.get_perms(&path, None)?.discover();
                Task::next(uuid, header, Self::new(discover))
            },
            Self::new(key) => {
                Task::waiting(uuid, header.clone(), Callback::new(Self::Complete), vec![
                    Task::Request(header, AgentRequest::ReadPrivate(key))
                ])
            },
            Self::Complete(mut responses) => {
                let response = *responses.remove(0).downcast::<DwnResponse>()?;
                let exists: bool = matches!(response, DwnResponse::ReadPrivate(Some(_)));
                Task::completed(uuid, exists)
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum ReadIndex {
    #[allow(non_camel_case_types)]
    new(RecordPath),
    Complete(Responses),
}

#[async_trait::async_trait]
impl<'a> Command<'a> for ReadIndex {
    async fn process(
        self: Box<Self>, uuid: Uuid, header: Header,
        memory: &mut CompilerMemory<'a>, _: &mut CompilerCache
    ) -> Result<Tasks<'a>, Error> {
        match *self {
            Self::new(path) => {
                let perms = memory.key.get_perms(&path.index(), Some(&SystemProtocols::usize()))?;
                Task::waiting(uuid, header.clone(), Callback::new(Self::Complete), vec![
                    Task::ready(header, ReadPrivate::new(Box::new(perms), false))
                ])
            }
            Self::Complete(mut results) => {
                let record = results.remove(0).downcast::<(Option<Box<PrivateRecord>>, bool)>()?.0;
                let payload = record.map(|r|
                    serde_json::from_slice::<usize>(&r.payload)
                ).transpose()?;
                Task::completed(uuid, payload.unwrap_or_default())
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct CreateDM {
    perms: PermissionSet,
    recipient: Did,
}

impl CreateDM {
    pub fn new(perms: PermissionSet, recipient: Did) -> Self {
        CreateDM{perms, recipient}
    }
}

#[async_trait::async_trait]
impl<'a> Command<'a> for CreateDM {
    async fn process(
        self: Box<Self>, uuid: Uuid, header: Header,
        memory: &mut CompilerMemory<'a>, _: &mut CompilerCache
    ) -> Result<Tasks<'a>, Error> {
        let signer = Signer::Left(memory.sig_key.clone());
        let (_, com_key) = memory.did_resolver.resolve_dwn_keys(&self.recipient).await?;
        Task::waiting(uuid, header.clone(), Callback::new(EnsureEmpty::new), vec![
            Task::MutableRequest(header, MutableAgentRequest::create_dm(self.perms, signer, com_key)?, 0)
        ])
    }

    async fn get_endpoints(
        &self, _: Vec<Did>, did_resolver: &dyn DidResolver
    ) -> Result<Vec<Endpoint>, Error> {
        let endpoints = did_resolver.get_endpoints(&[self.recipient.clone()]).await?;
        if endpoints.is_empty() {panic!("Did set had no endpoints");}
        Ok(endpoints)
    }
}

//  #[derive(Debug, Clone)]
//  pub struct ReadDM {
//      timestamp: DateTime<Utc>
//  }

//  impl ReadDM {
//      pub fn new(timestamp: DateTime<Utc>) -> Self {
//          ReadDM{timestamp}
//      }
//  }

//  #[async_trait::async_trait]
//  impl<'a> Command<'a> for ReadDM {
//      async fn process(
//          self: Box<Self>, uuid: Uuid, ep: Endpoint, mem: &mut CompilerMemory<'a>
//      ) -> Result<Tasks<'a>, Error> {
//          let signer = Signer::Left(mem.sig_key.clone());
//          
//          Task::waiting(uuid, ep.clone(), Callback::new(EnsureEmpty::new), vec![
//              Task::Request(ep, AgentRequest::create_dm(self.perms, signer, com_key)?)
//          ])
//      }
//  }

#[derive(Debug, Clone)]
pub enum Scan {
    #[allow(non_camel_case_types)]
    new(RecordPath, usize),
    Scanning(RecordPath, Vec<PrivateRecord>, usize, Option<Responses>),
}

#[async_trait::async_trait]
impl<'a> Command<'a> for Scan {
    async fn process(
        self: Box<Self>, uuid: Uuid, header: Header,
        _: &mut CompilerMemory<'a>, _: &mut CompilerCache
    ) -> Result<Tasks<'a>, Error> {
        match *self {
            Self::new(path, start) => {
                Task::next(uuid, header, Self::Scanning(path, vec![], start, None))
            },
            Self::Scanning(path, mut results, index, responses) => {
                if let Some(responses) = responses {
                    for response in responses {
                        match *response.downcast::<(Option<Box<PrivateRecord>>, bool)>()? {
                            (Some(record), _) => results.push(*record),
                            (_, true) => {},
                            (None, _) => {return Task::completed(uuid, results);}
                        }
                    }
                }
                let batch = if index >= 5 {index*2} else {5};
                let requests = (0..batch).map(|i| {
                    println!("Scanning index {}", index+i);
                    Task::ready(header.clone(), ReadPrivate::child(path.clone(), index+i))
                }).collect::<Vec<_>>();

                let callback = move |r: Responses| {Self::Scanning(path, results, batch+index, Some(r))};
                Task::waiting(uuid, header, Callback::new(callback), requests)
            }
        }
    }
}
