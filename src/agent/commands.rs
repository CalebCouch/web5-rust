use super::Error;

use super::compiler::CompilerMemory;
use super::permission::{PermissionOptions, PermissionSet};
use super::protocol::SystemProtocols;
use super::traits::Command;
use super::structs::{
    PrivateRecord,
    AgentRequest,
    RecordPath,
    RecordInfo,
    Responses,
    Callback,
    Record,
    Tasks,
    Task,
};

use crate::dids::signing::{SignedObject, Signer};
use crate::dids::{DidResolver, Endpoint, Did};
use crate::dwn::structs::DwnResponse;

use simple_crypto::SecretKey;
use serde::Serialize;
use uuid::Uuid;

#[derive(Serialize, Debug, Clone)]
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
        self: Box<Self>, uuid: Uuid, _: Endpoint, _: &mut CompilerMemory
    ) -> Result<Tasks<'a>, Error> {
        for response in self.responses {
            if response.downcast_ref::<()>().is_some() {} else {
                (*response.downcast::<DwnResponse>()?).into_empty()?;
            }
        }
        Task::completed(uuid, ())
    }
}

#[derive(Serialize, Debug, Clone)]
pub struct CreatePrivate {}
impl CreatePrivate {
    pub fn create(
        ep: Endpoint, mem: &mut CompilerMemory, record: Record, p_opts: Option<&PermissionOptions>
    ) -> Result<(PermissionSet, AgentRequest), Error> {
        let protocol = mem.get_protocol(&record.protocol)?;
        let perms = mem.key.get_perms(&record.path, Some(protocol))?;
        let min_perms = protocol.subset_permission(perms.clone(), None)?;
        let req = AgentRequest::create_private(0, perms.clone(), p_opts, protocol, record.payload)?;

        mem.record_info.insert((ep, record.path.clone()), (protocol.clone(), perms));

        Ok((min_perms, req))
    }

    pub fn create_child(
        ep: Endpoint, mem: &mut CompilerMemory,
        parent_perms: &PermissionSet, child_perms: &PermissionSet, index: usize
    ) -> Result<(AgentRequest, AgentRequest), Error> {
        let index_key = (ep, parent_perms.path.clone());
        let index = mem.create_index.get(&index_key).copied().unwrap_or(index);
        mem.create_index.insert(index_key, index+1);

        let index_perms = mem.key.get_perms(&parent_perms.path.index(), None)?;
        let index_req = AgentRequest::update_index(index_perms, index+1)?;
        let child_req = AgentRequest::create_private_child(0, parent_perms, child_perms, index)?;
        Ok((index_req, child_req))
    }
}

#[derive(Serialize, Debug, Clone)]
pub enum ReadPrivate {
    #[allow(non_camel_case_types)]
    child(RecordPath, usize),
    ChildInfo(Responses, usize),
    #[allow(non_camel_case_types)]
    path(RecordPath),
    #[allow(non_camel_case_types)]
    new(Box<PermissionSet>, bool),
    Complete(Responses, Box<PermissionSet>, bool),
}

impl ReadPrivate {
    fn read_private(
        perms: &PermissionSet, mem: &CompilerMemory, response: &DwnResponse
    ) -> Result<Option<PrivateRecord>, Error> {
        let discover = perms.discover.public_key();
        let create = perms.create.public_key();
        let read = perms.read.secret_key().ok_or(Error::invalid_auth("Read"))?;

        if let DwnResponse::ReadPrivate(item) = response {
            if let Some(item) = item {
                let dc = read.decrypt(&item.payload)?;
                let signed = serde_json::from_slice::<SignedObject<PrivateRecord>>(&dc)?;
                let mut record = signed.verify_with_key(&create)?;
                let protocol = mem.get_protocol(&record.protocol)?;
                let perms = protocol.trim_permission(perms.clone());
                let delete = perms.delete.as_ref().map(|d| d.public_key());
                perms.validate(&record.perms)?;
                protocol.validate_payload(&record.payload)?;
                protocol.validate_permission(&record.perms)?;
                if item.discover != discover || item.delete != delete {
                    return Err(Error::bad_response("Internal and External Key Mismatch"));
                }
                record.perms = record.perms.combine(perms)?;
                Ok(Some(record))
            } else {Ok(None)}
        } else {Err(Error::bad_response(&format!("Expected ReadPrivate(_) got {:?}", response)))}
    }
}

#[async_trait::async_trait]
impl<'a> Command<'a> for ReadPrivate {
    async fn process(
        self: Box<Self>, uuid: Uuid, ep: Endpoint, mem: &mut CompilerMemory<'a>
    ) -> Result<Tasks<'a>, Error> {
        match *self {
            Self::child(parent_path, index) => {
                let callback = move |r: Responses| {Self::ChildInfo(r, index)};
                Task::waiting(uuid, ep.clone(), Callback::new(callback), vec![
                    Task::ready(ep, ReadInfo::new(parent_path, PermissionOptions::read_child()))
                ])
            },
            Self::ChildInfo(mut responses, index) => {
                let info = *responses.remove(0).downcast::<RecordInfo>()?;
                let perms = info.1.pointer(index)?;
                Task::next(uuid, ep, Self::new(Box::new(perms), true))
            },
            Self::path(path) => {
                if path.is_empty() {
                    let protocol = SystemProtocols::root();
                    Task::completed(uuid, Some(Box::new(
                        PrivateRecord::new(mem.key.get_perms_from_slice(&[], Some(&protocol))?, protocol.uuid(), Vec::new())
                    )))
                } else {
                    let perms = mem.key.get_perms(&path, None)?;
                    Task::next(uuid, ep, Self::new(Box::new(perms), true))
                }
            },
            Self::new(perms, resolve) => {
                let req = AgentRequest::read_private(perms.discover())?;
                let callback = move |r: Responses| {Self::Complete(r, Box::new(*perms), resolve)};
                Task::waiting(uuid, ep.clone(), Callback::new(callback), vec![
                    Task::Request(ep, req)
                ])
            }
            Self::Complete(mut results, perms, resolve) => {
                let res = results.remove(0).downcast::<DwnResponse>()?;
                let record = Self::read_private(&perms, mem, &res).ok().flatten();
                let record = if let Some(record) = record {
                    if resolve && record.protocol == SystemProtocols::perm_pointer().uuid() {
                        let perms: PermissionSet = serde_json::from_slice(&record.payload)?;
                        let req = AgentRequest::read_private(perms.discover())?;
                        let callback = move |r: Responses| {Self::Complete(r, Box::new(perms), false)};
                        return Task::waiting(uuid, ep.clone(), Callback::new(callback), vec![
                            Task::Request(ep, req)
                        ]);
                    }
                    if let Ok(protocol) = mem.get_protocol(&record.protocol) {
                        mem.record_info.insert(
                            (ep.clone(), perms.path.clone()),
                            (protocol.clone(), record.perms.clone())
                        );
                    }
                    Some(Box::new(record))
                } else {None};
                Task::completed(uuid, record)
            },
        }
    }
}

#[derive(Serialize, Debug, Clone)]
pub enum ReadInfo {
    #[allow(non_camel_case_types)]
    new(RecordPath, PermissionOptions),
    Complete(Responses)
}

#[async_trait::async_trait]
impl<'a> Command<'a> for ReadInfo {
    async fn process(
        self: Box<Self>, uuid: Uuid, ep: Endpoint, mem: &mut CompilerMemory<'a>
    ) -> Result<Tasks<'a>, Error> {
        match *self {
            Self::new(path, p_opts) => {
                match mem.record_info.get(&(ep.clone(), path.clone())) {
                    Some(info) if info.clone().1.subset(&p_opts).is_ok() => {
                        Task::completed(uuid, info.clone())
                    },
                    _ => {
                        Task::waiting(uuid, ep.clone(), Callback::new(Self::Complete), vec![
                            Task::ready(ep, ReadPrivate::path(path))
                        ])
                    }
                }
            }
            Self::Complete(mut results) => {
                let record = *results.remove(0).downcast::<Option<Box<PrivateRecord>>>()?;
                if let Some(record) = record {
                    Task::completed(uuid, (mem.get_protocol(&record.protocol)?.clone(), record.perms))
                } else {Err(Error::not_found("Record information"))}
            },
        }
    }
}

#[derive(Serialize, Debug, Clone)]
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
        self: Box<Self>, uuid: Uuid, ep: Endpoint, mem: &mut CompilerMemory
    ) -> Result<Tasks<'a>, Error> {
        let parent_path = self.path.parent()?;
        if parent_path.is_empty() {
            let protocol = SystemProtocols::root();
            Task::completed(uuid, Some(Box::new(
                PrivateRecord::new(mem.key.get_perms_from_slice(&[], Some(&protocol))?, protocol.uuid(), Vec::new())
            )))
        } else {
            let perms = mem.key.get_perms(&parent_path, None)?;
            Task::next(uuid, ep, ReadPrivate::new(Box::new(perms), true))
        }
    }
}

#[derive(Serialize, Debug, Clone)]
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
        self: Box<Self>, uuid: Uuid, ep: Endpoint, _: &mut CompilerMemory
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
        Task::waiting(uuid, ep.clone(), Callback::new(callback), vec![
            Task::Ready(ep, Box::new(Exists::new(discover)))
        ])
    }
}

#[derive(Serialize, Debug, Clone)]
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
        self: Box<Self>, uuid: Uuid, ep: Endpoint, mem: &mut CompilerMemory<'a>
    ) -> Result<Tasks<'a>, Error> {
        match *self {
            Self::path(path) => {
                let discover = mem.key.get_perms(&path, None)?.discover();
                Task::next(uuid, ep, Self::new(discover))
            },
            Self::new(key) => {
                Task::waiting(uuid, ep.clone(), Callback::new(Self::Complete), vec![
                    Task::Request(ep, AgentRequest::read_private(key)?)
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

#[derive(Serialize, Debug, Clone)]
pub enum ReadIndex {
    #[allow(non_camel_case_types)]
    new(RecordPath),
    Complete(Responses),
}

#[async_trait::async_trait]
impl<'a> Command<'a> for ReadIndex {
    async fn process(
        self: Box<Self>, uuid: Uuid, ep: Endpoint, mem: &mut CompilerMemory
    ) -> Result<Tasks<'a>, Error> {
        match *self {
            Self::new(path) => {
                let perms = mem.key.get_perms(&path.index(), Some(&SystemProtocols::usize()))?;
                Task::waiting(uuid, ep.clone(), Callback::new(Self::Complete), vec![
                    Task::ready(ep, ReadPrivate::new(Box::new(perms), false))
                ])
            }
            Self::Complete(mut results) => {
                let record = results.remove(0).downcast::<Option<Box<PrivateRecord>>>()?;
                let payload = record.map(|r|
                    serde_json::from_slice::<usize>(&r.payload)
                ).transpose()?;
                Task::completed(uuid, payload.unwrap_or_default())
            },
        }
    }
}

#[derive(Serialize, Debug, Clone)]
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
        self: Box<Self>, uuid: Uuid, ep: Endpoint, mem: &mut CompilerMemory<'a>
    ) -> Result<Tasks<'a>, Error> {
        let signer = Signer::Left(mem.sig_key.clone());
        let (_, com_key) = mem.did_resolver.resolve_dwn_keys(&self.recipient).await?;
        Task::waiting(uuid, ep.clone(), Callback::new(EnsureEmpty::new), vec![
            Task::Request(ep, AgentRequest::create_dm(self.perms, signer, com_key)?)
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

//  #[derive(Serialize, Debug, Clone)]
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
