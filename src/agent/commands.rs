use super::Error;

use super::compiler::{CompilerMemory, CompilerCache};
use super::permission::{PermissionOptions, PermissionSet};
use super::protocol::{SystemProtocols, Protocol};
use super::traits::{Response, Command, TypeDebug};
use super::structs::{
    MutableAgentRequest,
    PrivateRecord,
    AgentRequest,
    RecordPath,
    RecordInfo,
    BoxCommand,
    Responses,
    Callback,
    Header,
    Record,
    Tasks,
    Task,
};

use crate::dids::signing::{SignedObject, Verifier, Signer};
use crate::dids::Did;
use crate::dwn::structs::{PublicRecord, DwnResponse, DwnItem};

use std::collections::BTreeMap;

use simple_database::database::{IndexBuilder, SortOptions, Filters, Filter};
use simple_database::Indexable;
use simple_crypto::{Hashable, SecretKey, PublicKey};
use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

#[derive(Serialize, Debug, Clone)]
pub struct Complete {
    response: Box<dyn Response>
}
impl Complete {
    pub fn new_first(mut responses: Responses) -> Self {Complete{response: responses.remove(0)}}
    pub fn new(responses: Responses) -> Self {Complete{response: Box::new(responses)}}
}

#[async_trait::async_trait]
impl Command for Complete {
    async fn process<'a>(mut self: Box<Self>, uuid: Uuid, _: Header, _: &mut CompilerMemory, _: &mut CompilerCache) -> Result<Tasks, Error> {
        Ok(vec![(uuid, Task::Completed(self.response))])
    }
}
impl Hashable for Complete {}

#[derive(Serialize, Debug, Clone)]
pub struct EnsureEmpty {
    responses: Responses
}

impl EnsureEmpty {
    pub fn new(responses: Responses) -> Self {
        EnsureEmpty{responses}
    }

    pub fn is_empty(responses: Responses) -> Result<(), Error> {
        for response in responses {
            match response {
                response if response.downcast_ref::<()>().is_some() => {},
                response if response.downcast_ref::<DwnResponse>().is_some() =>
                    (*response.downcast::<DwnResponse>()?).into_empty()?,
                _ => Self::is_empty(*response.downcast::<Responses>()?)?
            }
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl Command for EnsureEmpty {
    async fn process<'a>(
        self: Box<Self>, uuid: Uuid, _: Header,
        _: &mut CompilerMemory, _: &mut CompilerCache
    ) -> Result<Tasks, Error> {
        Task::completed(uuid, Self::is_empty(self.responses)?)
    }
}
impl Hashable for EnsureEmpty {}

#[derive(Serialize, Debug, Clone)]
pub enum CreatePrivate {
    #[allow(non_camel_case_types)]
    new(Record, Option<PermissionOptions>),
    Create(Responses, Record, Option<PermissionOptions>),
}

#[async_trait::async_trait]
impl Command for CreatePrivate {
    async fn process<'a>(
        self: Box<Self>, uuid: Uuid, header: Header,
        memory: &mut CompilerMemory, cache: &mut CompilerCache
    ) -> Result<Tasks, Error> {
        match *self {
            Self::new(record, p_opts) => {
                println!("Start Create");
                let parent_path = record.path.parent()?;
                let path = record.path.clone();
                let callback = move |r: Responses| {Self::Create(r, record, p_opts)};
                Task::waiting(uuid, header.clone(), Callback::new(callback), vec![
                    Task::ready(header.clone(), ReadPrivate::path(path)),
                    Task::ready(header, ReadInfo::new(parent_path, PermissionOptions::create_child())),
                ])
            },
            Self::Create(mut results, record, p_opts) => {
                match *results.remove(0).downcast::<(Option<Box<PrivateRecord>>, bool)>()? {
                    (Some(precord), true) if precord.clone().into_record().hash() == record.hash() => {
                        return Task::completed(uuid, ());
                    },
                    (_, true) => {return Task::completed(uuid, "Conflict");},
                    _ => {
                        let perms = memory.get_perms(header.enc, &record.path, Some(&record.protocol))?;
                        let min_perms = record.protocol.subset_permission(perms.clone(), None)?;
                        let req = MutableAgentRequest::create_private(
                            perms.clone(), p_opts.as_ref(), record.protocol.clone(), record.payload
                        )?;

                        cache.record_info.insert(
                            (header.endpoint.clone(), header.enc, record.path.clone()),
                            (record.protocol, perms)
                        );

                        println!("Creating Index and Req");
                        Task::waiting(uuid, header.clone(), Callback::new(EnsureEmpty::new), vec![
                            Task::ready(header.clone(), CreatePrivateChild::new(
                                record.path.parent()?, Box::new(min_perms)
                            )),
                            Task::MutableRequest(header, req, 0)
                        ])
                    }
                }
            }
        }
    }
}
impl Hashable for CreatePrivate {}

#[derive(Serialize, Debug, Clone)]
pub enum CreatePrivateChild {
    #[allow(non_camel_case_types)]
    new(RecordPath, Box<PermissionSet>),
    Create(Responses, RecordPath, Box<PermissionSet>)
}

#[async_trait::async_trait]
impl Command for CreatePrivateChild {
    async fn process<'a>(
        self: Box<Self>, uuid: Uuid, header: Header,
        memory: &mut CompilerMemory, _: &mut CompilerCache
    ) -> Result<Tasks, Error> {
        match *self {
            Self::new(path, perms) => {
                println!("Starting cerate cIld: readinfo, nextindex");
                let path_copy = path.clone();
                let callback = move |r: Responses| {Self::Create(r, path_copy, perms)};
                Task::waiting(uuid, header.clone(), Callback::new(callback), vec![
                    Task::ready(header.clone(), ReadInfo::new(path.clone(), PermissionOptions::create_child())),
                    Task::ready(header, NextIndex::new(path))
                ])
            },
            Self::Create(mut results, path, perms) => {
                println!("Creating Child");
                results.remove(1).downcast::<()>()?;
                let info = *results.remove(0).downcast::<RecordInfo>()?;

                let index_perms = memory.get_perms(header.enc, &path.index(), None)?;

                let index_key = (header.endpoint.clone(), header.enc, path);
                let index = memory.create_index.get(&index_key).unwrap()+1;
                memory.create_index.insert(index_key, index);

                let index_req = MutableAgentRequest::update_index(index_perms, index)?;
                let child_req = MutableAgentRequest::create_private_child(&info.1, &perms, index)?;
                Task::waiting(uuid, header.clone(), Callback::new(EnsureEmpty::new), vec![
                    Task::MutableRequest(header.clone(), index_req, index),
                    Task::MutableRequest(header.clone(), child_req, 0),
                ])
            }
        }
    }
}
impl Hashable for CreatePrivateChild {}

#[derive(Serialize, Debug, Clone)]
pub enum UpdatePrivate {
    #[allow(non_camel_case_types)]
    new(Record, Option<PermissionOptions>),
    UpdateOrCreate(Responses, Record, Option<PermissionOptions>),
}

#[async_trait::async_trait]
impl Command for UpdatePrivate {
    async fn process<'a>(
        self: Box<Self>, uuid: Uuid, header: Header,
        _: &mut CompilerMemory, _: &mut CompilerCache
    ) -> Result<Tasks, Error> {
        match *self {
            Self::new(record, p_opts) => {
                let path = record.path.clone();
                let callback = move |r: Responses| {Self::UpdateOrCreate(r, record, p_opts)};
                Task::waiting(uuid, header.clone(), Callback::new(callback), vec![
                    Task::ready(header.clone(), ReadInfo::new(path.clone(), PermissionOptions::update())),
                    Task::ready(header, ReadPrivate::path(path)),
                ])
            },
            Self::UpdateOrCreate(mut r, record, p_opts) => {
                match *r.remove(1).downcast::<(Option<Box<PrivateRecord>>, bool)>()? {
                    (Some(_), _) => {
                        let perms = r.remove(0).downcast::<RecordInfo>()?.1;
                        let req = MutableAgentRequest::update_private(
                            perms, p_opts.as_ref(), record.protocol, record.payload
                        )?;
                        let order = header.order;
                        Task::waiting(uuid, header.clone(),
                            Callback::new(EnsureEmpty::new), vec![
                            Task::MutableRequest(header, req, order)
                        ])
                    },
                    (old_record, exists) => {
                        Task::next(uuid, header, CreatePrivate::Create(
                            vec![Box::new((old_record, exists))], record, p_opts
                        ))
                    }
                }
            },
        }
    }
}
impl Hashable for UpdatePrivate {}

#[derive(Serialize, Debug, Clone)]
pub enum ReadPrivate {
    #[allow(non_camel_case_types)]
    path(RecordPath),
    #[allow(non_camel_case_types)]
    new(Box<PermissionSet>, bool),
    Complete(Responses, Box<PermissionSet>, bool, bool),
}

impl ReadPrivate {
    fn read_private(
        perms: &PermissionSet, response: &DwnResponse
    ) -> Result<(Option<PrivateRecord>, bool), Error> {
        let discover = perms.discover.public_key();
        let create = perms.create.public_key();
        let read = perms.read.secret_key().ok_or(Error::invalid_auth("Read"))?;

        if let DwnResponse::ReadPrivate(item) = response {
            if let Some(item) = item {
                let dc = read.decrypt(&item.payload)?;
                let signed = serde_json::from_slice::<SignedObject<PrivateRecord>>(&dc)?;
                let mut record = signed.verify_with_key(&create)?;
                let perms = record.protocol.trim_permission(perms.clone());
                let delete = perms.delete.as_ref().map(|d| d.public_key());
                perms.validate(&record.perms)?;
                record.protocol.validate_payload(&record.payload)?;
                record.protocol.validate_permission(&record.perms)?;
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
impl Command for ReadPrivate {
    async fn process<'a>(
        self: Box<Self>, uuid: Uuid, header: Header,
        memory: &mut CompilerMemory, cache: &mut CompilerCache
    ) -> Result<Tasks, Error> {
        match *self {
            Self::path(path) => {
                if path.is_empty() {
                    let protocol = SystemProtocols::root();
                    Task::completed(uuid, (Some(Box::new(
                        PrivateRecord::new(memory.get_perms(header.enc, &RecordPath::root(), Some(&protocol))?, protocol, Vec::new())
                    )), true))
                } else {
                    let perms = memory.get_perms(header.enc, &path, None)?;
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
                let record = if let Ok((record, nexists)) = Self::read_private(&perms, &res) {
                    let exists = exists || nexists;
                    if let Some(record) = record {
                        if resolve && record.protocol == SystemProtocols::perm_pointer() {
                            let perms: PermissionSet = serde_json::from_slice(&record.payload)?;
                            let req = AgentRequest::ReadPrivate(perms.discover());
                            let callback = move |r: Responses| {Self::Complete(r, Box::new(perms), false, exists)};
                            return Task::waiting(uuid, header.clone(), Callback::new(callback), vec![
                                Task::Request(header, req)
                            ]);
                        }
                        cache.record_info.insert(
                            (header.endpoint.clone(), header.enc, perms.path.clone()),
                            (record.protocol.clone(), record.perms.clone())
                        );
                        (Some(Box::new(record)), exists)
                    } else {(None, exists)}
                } else {(None, exists)};
                Task::completed(uuid, record)
            },
        }
    }
}
impl Hashable for ReadPrivate {}

#[derive(Serialize, Debug, Clone)]
pub enum ReadPrivateChild {
    #[allow(non_camel_case_types)]
    new(RecordPath, usize),
    Info(Responses, usize),
    Complete(Responses, Protocol),
}

#[async_trait::async_trait]
impl Command for ReadPrivateChild {
    async fn process<'a>(
        self: Box<Self>, uuid: Uuid, header: Header,
        _: &mut CompilerMemory, _: &mut CompilerCache
    ) -> Result<Tasks, Error> {
        match *self {
            Self::new(parent_path, index) => {
                let callback = move |r: Responses| {Self::Info(r, index)};
                Task::waiting(uuid, header.clone(), Callback::new(callback), vec![
                    Task::ready(header, ReadInfo::new(parent_path, PermissionOptions::read_child()))
                ])
            },
            Self::Info(mut responses, index) => {
                let info = *responses.remove(0).downcast::<RecordInfo>()?;
                let perms = info.1.pointer(index)?;
                let callback = move |r: Responses| {Self::Complete(r, info.0)};
                Task::waiting(uuid, header.clone(), Callback::new(callback), vec![
                    Task::ready(header, ReadPrivate::new(Box::new(perms), true))
                ])
            },
            Self::Complete(mut r, parent_protocol) => {
                let mut child = *r.remove(0).downcast::<(Option<Box<PrivateRecord>>, bool)>()?;
                child.0.as_mut().filter(|c| parent_protocol.validate_child(&c.protocol.uuid()).is_ok());
                Task::completed(uuid, child)
            }
        }
    }
}
impl Hashable for ReadPrivateChild {}

#[derive(Serialize, Debug, Clone)]
pub enum ReadInfo {
    #[allow(non_camel_case_types)]
    new(RecordPath, PermissionOptions),
    Complete(Responses)
}

#[async_trait::async_trait]
impl Command for ReadInfo {
    async fn process<'a>(
        self: Box<Self>, uuid: Uuid, header: Header,
        _: &mut CompilerMemory, cache: &mut CompilerCache
    ) -> Result<Tasks, Error> {
        match *self {
            Self::new(path, p_opts) => {
                match cache.record_info.get(&(header.endpoint.clone(), header.enc, path.clone())) {
                    Some(info) if info.clone().1.subset(&p_opts).is_ok() => {
                        Task::completed(uuid, info.clone())
                    },
                    _ => {
                        println!("Reading Info");
                        Task::waiting(uuid, header.clone(), Callback::new(Self::Complete), vec![
                            Task::ready(header, ReadPrivate::path(path))
                        ])
                    }
                }
            }
            Self::Complete(mut results) => {
                let record = results.remove(0).downcast::<(Option<Box<PrivateRecord>>, bool)>()?.0;
                if let Some(record) = record {
                    cache.record_info.insert(
                        (header.endpoint, header.enc, record.perms.path.clone()),
                        (record.protocol.clone(), record.perms.clone())
                    );
                    Task::completed(uuid, (record.protocol, record.perms))
                } else {Err(Error::not_found("Record information"))}
            },
        }
    }
}
impl Hashable for ReadInfo {}


/*
    GetNextIndex when provided with a discover_child key will scan to get the latest
    unused index of the channel. This function is expected to run before any create
    private child command, Only one command should be running per key so serialization
    only covers the discover_child field.
*/
//TODO: Only Hash the path
#[derive(Serialize, Debug, Clone)]
pub enum NextIndex {
    #[allow(non_camel_case_types)]
    new(RecordPath),
    GetIndex(Responses, RecordPath),
    Recursion(Option<Responses>, RecordPath, SecretKey, usize),
}

#[async_trait::async_trait]
impl Command for NextIndex {
    async fn process<'a>(
        self: Box<Self>, uuid: Uuid, header: Header,
        memory: &mut CompilerMemory, _: &mut CompilerCache
    ) -> Result<Tasks, Error> {
        match *self {
            Self::new(path) => {
                println!("Starting NextIndex");
                let index_key = (header.endpoint.clone(), header.enc, path.clone());
                if memory.create_index.contains_key(&index_key) {
                    return Task::completed(uuid, ());
                }
                let path_copy = path.clone();
                let callback = move |r: Responses| {Self::GetIndex(r, path_copy)};
                println!("ReadInfo:ReadIndex");
                Task::waiting(uuid, header.clone(), Callback::new(callback), vec![
                    Task::ready(header.clone(), ReadInfo::new(path.clone(), PermissionOptions::create_child())),
                    Task::ready(header.clone(), ReadIndex::path(path))
                ])
            },
            Self::GetIndex(mut results, path) => {
                let index = *results.remove(1).downcast::<usize>()?;
                let key = results.remove(0).downcast::<RecordInfo>()?.1.discover_child()?;

                Task::next(uuid, header, Self::Recursion(None, path, key, index))
            }
            Self::Recursion(results, path, discover_child, mut index) => {
                let index_key = (header.endpoint.clone(), header.enc, path.clone());
                if memory.create_index.contains_key(&index_key) {
                    return Task::completed(uuid, ());
                }
                if let Some(mut results) = results {
                    if *results.remove(0).downcast::<bool>()? {
                        index += 1;
                    } else {
                        memory.create_index.insert(index_key, index);
                        return Task::completed(uuid, ());
                    }
                }
                let discover = discover_child.derive_usize(index)?;
                let callback = move |r: Responses| {Self::Recursion(Some(r), path, discover_child, index)};
                println!("Reading Child");
                Task::waiting(uuid, header.clone(), Callback::new(callback), vec![
                    Task::Ready(header, Box::new(Exists::new(discover)))
                ])
            }
        }
    }

    fn serialize(&self) -> String {
        let path = match &self {
            Self::new(path) => path,
            Self::GetIndex(_, path) => path,
            Self::Recursion(_, path, _, _) => path,
        };
        format!(
            "{}::{}",
            (*self).get_full_type(),
            path
        )
    }
}

impl Hashable for NextIndex {}

#[derive(Serialize, Debug, Clone)]
pub enum Exists {
    #[allow(non_camel_case_types)]
    new(SecretKey),
    Complete(Responses),
}

#[async_trait::async_trait]
impl Command for Exists {
    async fn process<'a>(
        self: Box<Self>, uuid: Uuid, header: Header,
        _: &mut CompilerMemory, _: &mut CompilerCache
    ) -> Result<Tasks, Error> {
        match *self {
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
impl Hashable for Exists {}

#[derive(Serialize, Debug, Clone)]
pub enum ReadIndex {
    #[allow(non_camel_case_types)]
    path(RecordPath),
    #[allow(non_camel_case_types)]
    new(Box<PermissionSet>),
    Complete(Responses),
}

#[async_trait::async_trait]
impl Command for ReadIndex {
    async fn process<'a>(
        self: Box<Self>, uuid: Uuid, header: Header,
        memory: &mut CompilerMemory, _: &mut CompilerCache
    ) -> Result<Tasks, Error> {
        match *self {
            Self::path(path) => {
                let perms = memory.get_perms(header.enc, &path.index(), Some(&SystemProtocols::usize()))?;
                Task::next(uuid, header, Self::new(Box::new(perms)))
            },
            Self::new(perms) => {
                Task::waiting(uuid, header.clone(), Callback::new(Self::Complete), vec![
                    Task::ready(header, ReadPrivate::new(perms, false))
                ])
            },
            Self::Complete(mut results) => {
                let record = results.remove(0).downcast::<(Option<Box<PrivateRecord>>, bool)>()?.0;
                let payload = record.map(|r|
                    serde_json::from_slice::<usize>(&r.payload)
                ).transpose()?;
                Task::completed(uuid, payload.unwrap_or_default())
            }
        }
    }
}
impl Hashable for ReadIndex {}

#[derive(Serialize, Debug, Clone)]
pub struct Send {
    command: BoxCommand,
    recipients: Vec<Did>
}

impl Send {
    #[allow(non_snake_case)]
    pub fn New(command: Box<dyn Command>, recipients: Vec<Did>) -> Self {
        Send{command, recipients}
    }
    pub fn new(command: (impl Command + 'static), recipients: Vec<Did>) -> Self {
        Send{command: Box::new(command), recipients}
    }
}

#[async_trait::async_trait]
impl Command for Send {
    async fn process<'a>(
        self: Box<Self>, uuid: Uuid, header: Header,
        memory: &mut CompilerMemory, _: &mut CompilerCache
    ) -> Result<Tasks, Error> {
        let endpoints = memory.did_resolver.get_endpoints(&self.recipients).await?;
        let tasks = endpoints.into_iter().map(|ep| {
            let mut header = header.clone();
            header.endpoint = ep;
            Task::Ready(header, self.command.clone())
        }).collect::<Vec<_>>();
        Task::waiting(uuid, header.clone(), Callback::new(Complete::new), tasks)
    }
}
impl Hashable for Send {}

#[derive(Serialize, Debug, Clone)]
pub enum CreateDM {
    #[allow(non_camel_case_types)]
    new(PermissionSet, Did),
    Request(PermissionSet, Did)
}

#[async_trait::async_trait]
impl Command for CreateDM {
    async fn process<'a>(
        self: Box<Self>, uuid: Uuid, header: Header,
        memory: &mut CompilerMemory, _: &mut CompilerCache
    ) -> Result<Tasks, Error> {
        match *self {
            Self::new(perms, recipient) => {
                Task::next(uuid, header, Send::new(Self::Request(perms, recipient.clone()), vec![recipient]))
            },
            Self::Request(perms, recipient) => {
                let (_, com_key) = memory.did_resolver.resolve_dwn_keys(&recipient).await?;
                let req = MutableAgentRequest::create_dm(perms, memory.signer(), com_key)?;
                Task::waiting(uuid, header.clone(), Callback::new(EnsureEmpty::new), vec![
                    Task::MutableRequest(header, req, 0)
                ])
            }
        }
    }
}
impl Hashable for CreateDM {}

#[derive(Serialize, Debug, Clone)]
pub enum ReadDM {
    #[allow(non_camel_case_types)]
    new(),
    Timestamp(Responses),
    Completed(Responses),
}

impl ReadDM {
    async fn read_dm<'a>(
        memory: &CompilerMemory<'a>, item: DwnItem
    ) -> Result<(Verifier, PermissionSet), Error> {
        let dc = memory.com_decrypt(&item.payload)?;
        let signed = serde_json::from_slice::<SignedObject<PermissionSet>>(&dc)?;
        let signer = signed.verify(memory.did_resolver, None).await?;
        Ok((signer, signed.unwrap()))
    }

    async fn read_dms<'a>(
        memory: &CompilerMemory<'a>, response: DwnResponse
    ) -> Result<Vec<(Verifier, PermissionSet)>, Error> {
        if let DwnResponse::ReadDM(items) = response {
            Ok(futures::future::join_all(items.into_iter().map(|item| async {
                Self::read_dm(memory, item).await.ok()
            })).await.into_iter().flatten().collect::<Vec<_>>())
        } else {Err(Error::bad_response(&format!("Expected ReadPrivate(_) got {:?}", response)))}
    }
}

#[async_trait::async_trait]
impl Command for ReadDM {
    async fn process<'a>(
        self: Box<Self>, uuid: Uuid, header: Header,
        memory: &mut CompilerMemory, _: &mut CompilerCache
    ) -> Result<Tasks, Error> {
        match *self {
            Self::new() => {
                let ldc_path = RecordPath::new(&[Uuid::new_v5(&Uuid::NAMESPACE_OID, b"LDC")]);
                let ldc_perms = memory.get_perms(false, &ldc_path, None)?;
                Task::waiting(uuid, header.clone(), Callback::new(Self::Timestamp), vec![
                    Task::ready(header.com(), ReadIndex::new(Box::new(ldc_perms)))
                ])

            },
            Self::Timestamp(mut responses) => {
                let timestamp = DateTime::<Utc>::from_timestamp(
                    *responses.remove(0).downcast::<usize>()? as i64, 0
                ).unwrap();
                Task::waiting(uuid, header.clone(), Callback::new(Self::Completed), vec![
                    Task::Request(header, AgentRequest::ReadDM(timestamp, memory.com_signer()))
                ])
            },
            Self::Completed(mut responses) => {
                let dwn_items = *responses.remove(0).downcast::<DwnResponse>()?;
                let path = RecordPath::new(&[]).index();
                let protocol = SystemProtocols::usize();
                let timestamp = Utc::now().timestamp() as usize;
                let req = MutableAgentRequest::update_private(
                    memory.get_perms(false, &path, Some(&protocol))?,
                    None, protocol, serde_json::to_vec(&timestamp)?
                )?;
                Ok(vec![
                    (uuid, Task::Completed(Box::new(Self::read_dms(memory, dwn_items).await?))),
                    (Uuid::new_v4(), Task::MutableRequest(header, req, timestamp))
                ])
            }
        }
    }
}
impl Hashable for ReadDM {}

#[derive(Serialize, Debug, Clone)]
pub enum ScanDM {
    #[allow(non_camel_case_types)]
    new(),
    Scan(Responses),
}

#[async_trait::async_trait]
impl Command for ScanDM {
    async fn process<'a>(
        self: Box<Self>, uuid: Uuid, header: Header,
        _: &mut CompilerMemory, _: &mut CompilerCache
    ) -> Result<Tasks, Error> {
        match *self {
            Self::new() => {
                Task::waiting(uuid, header.clone(), Callback::new(Self::Scan), vec![
                    Task::ready(header.clone(), ReadDM::new())
                ])
            },
            Self::Scan(mut responses) => {
                let channels = *responses.remove(0).downcast::<Vec<(Verifier, PermissionSet)>>()?;
                let tasks = channels.into_iter().map(|(sender, perms)| {
                    let path = RecordPath::new(&[Uuid::new_v5(
                        &Uuid::NAMESPACE_OID, sender.to_string().as_bytes()
                    )]);
                    let record = Record::new(
                        path, SystemProtocols::pointer(), &serde_json::to_vec(&perms)?
                    );
                    Ok(Task::ready(header.com(), UpdatePrivate::new(record, None)))
                }).collect::<Result<Vec<Task>, Error>>()?;
                Task::waiting(uuid, header, Callback::new(EnsureEmpty::new), tasks)
            }
        }
    }
}
impl Hashable for ScanDM {}

#[derive(Serialize, Debug, Clone)]
pub enum EstablishChannel {
    #[allow(non_camel_case_types)]
    new(Did),
    Read(Did),
    Create(Responses, Did, RecordPath),
  //ReadCreated(Responses, RecordPath),
  //Completed(Responses)
}

#[async_trait::async_trait]
impl Command for EstablishChannel {
    async fn process<'a>(
        self: Box<Self>, uuid: Uuid, header: Header,
        memory: &mut CompilerMemory, _: &mut CompilerCache
    ) -> Result<Tasks, Error> {
        match *self {
            Self::new(recipient) => {
                let callback = move |_: Responses| {Self::Read(recipient)};
                Task::waiting(uuid, header.clone(), Callback::new(callback), vec![
                    Task::ready(header.clone(), ScanDM::new())
                ])
            },
            Self::Read(recipient) => {
                let path = RecordPath::new(&[Uuid::new_v5(
                    &Uuid::NAMESPACE_OID, recipient.to_string().as_bytes()
                )]);
                let tasks = vec![Task::ready(header.com(), ReadPrivate::path(path.clone()))];
                let callback = move |r: Responses| {Self::Create(r, recipient, path)};
                Task::waiting(uuid, header.clone(), Callback::new(callback), tasks)
            },
            Self::Create(mut responses, recipient, path) => {
                match responses.remove(0).downcast::<(Option<Box<PrivateRecord>>, bool)>()?.0 {
                    Some(_) => Task::completed(uuid, ()),
                    None => {
                        let protocol = SystemProtocols::dms_channel();
                        let perms = memory.get_perms(false, &path, Some(&protocol))?;
                        let channel = Record::new(path.clone(), protocol, &[]);
                        Task::waiting(uuid, header.clone(), Callback::new(EnsureEmpty::new), vec![
                            Task::ready(header.com(), Send::new(
                                CreatePrivate::new(channel.clone(), None), vec![recipient.clone()]
                            )),
                            Task::ready(
                                header.com(), CreatePrivate::new(channel.clone(), None)
                            ),
                            Task::ready(header, CreateDM::new(perms, recipient))
                        ])
                    }
                }
            },
        }
    }
}
impl Hashable for EstablishChannel {}

#[derive(Serialize, Debug, Clone)]
pub enum Scan {
    #[allow(non_camel_case_types)]
    new(RecordPath, usize),
    Scanning(RecordPath, Vec<PrivateRecord>, usize, Option<Responses>),
}

#[async_trait::async_trait]
impl Command for Scan {
    async fn process<'a>(
        self: Box<Self>, uuid: Uuid, header: Header,
        _: &mut CompilerMemory, _: &mut CompilerCache
    ) -> Result<Tasks, Error> {
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
                    Task::ready(header.clone(), ReadPrivateChild::new(path.clone(), index+i))
                }).collect::<Vec<_>>();

                let callback = move |r: Responses| {Self::Scanning(path, results, batch+index, Some(r))};
                Task::waiting(uuid, header, Callback::new(callback), requests)
            }
        }
    }
}
impl Hashable for Scan {}

#[derive(Serialize, Debug, Clone)]
pub enum Init {
    #[allow(non_camel_case_types)]
    new(Vec<RecordPath>),
    Complete(Responses, Vec<RecordPath>),
}

#[async_trait::async_trait]
impl Command for Init {
    async fn process<'a>(
        self: Box<Self>, uuid: Uuid, header: Header,
        memory: &mut CompilerMemory, _: &mut CompilerCache
    ) -> Result<Tasks, Error> {
        match *self {
            Self::new(paths) => {
                let filters = Filters::new(vec![
                    ("signer", Filter::equal(memory.tenant().to_string())),
                    ("type", Filter::equal("agent_keys".to_string()))
                ]);

                let callback = move |r: Responses| {Self::Complete(r, paths)};
                Task::waiting(uuid, header.clone(), Callback::new(callback), vec![
                    Task::ready(header, ReadPublic::new(filters, None))
                ])
            },
            Self::Complete(mut responses, paths) => {
                let records = responses.remove(0).downcast::<Vec<PublicRecord>>()?;

                let record_id = records.first().map(|r| r.uuid);
                let mut agent_keys = records.first().and_then(|record|
                    serde_json::from_slice::<BTreeMap<RecordPath, PublicKey>>(&record.payload).ok()
                ).unwrap_or_default();

                match paths.into_iter().map(|path| {
                    let key = memory.get_pub(&path)?;
                    let o_key = agent_keys.insert(path, key.clone());
                    Ok(Some(key) == o_key)
                }).collect::<Result<Vec<bool>, Error>>()?
                .iter().all(|b| *b) {
                    true => Task::completed(uuid, ()),
                    false => {
                        let index = IndexBuilder::build(vec![("type", "agent_keys")])?;
                        let record = PublicRecord::new(
                            record_id, SystemProtocols::agent_keys(),
                            &serde_json::to_vec(&agent_keys)?, Some(index)
                        )?;
                        Ok(vec![(uuid, Task::ready(header, UpdatePublic::new(record, None)))])
                    }
                }
            }
        }
    }
}
impl Hashable for Init {}

#[derive(Serialize, Debug, Clone)]
pub struct DeletePrivate {
    path: RecordPath
}

impl DeletePrivate {
    pub fn new(path: RecordPath) -> Self {
        DeletePrivate{path}
    }
}

#[async_trait::async_trait]
impl Command for DeletePrivate {
    async fn process<'a>(
        self: Box<Self>, uuid: Uuid, header: Header,
        memory: &mut CompilerMemory, _: &mut CompilerCache
    ) -> Result<Tasks, Error> {
        let perms = memory.get_perms(header.enc, &self.path, None)?;
        let req = MutableAgentRequest::delete_private(&perms)?;
        let order = header.order;
        Task::waiting(uuid, header.clone(), Callback::new(EnsureEmpty::new), vec![
            Task::MutableRequest(header, req, order)
        ])
    }
}
impl Hashable for DeletePrivate {}

#[derive(Serialize, Debug, Clone)]
pub struct CreatePublic {
    record: PublicRecord,
    signer: Option<Signer>,
}

impl CreatePublic {
    pub fn new(record: PublicRecord, signer: Option<Signer>) -> Self {
        CreatePublic{record, signer}
    }
}

#[async_trait::async_trait]
impl Command for CreatePublic {
    async fn process<'a>(
        self: Box<Self>, uuid: Uuid, header: Header,
        memory: &mut CompilerMemory, _: &mut CompilerCache
    ) -> Result<Tasks, Error> {
        self.record.protocol.validate_payload(&self.record.payload)?;
        let signer = self.signer.unwrap_or(memory.signer());
        let req = MutableAgentRequest::create_public(self.record, signer)?;
        Task::waiting(uuid, header.clone(), Callback::new(EnsureEmpty::new), vec![
            Task::MutableRequest(header, req, 0)
        ])
    }
}
impl Hashable for CreatePublic {}

#[derive(Serialize, Debug, Clone)]
pub enum ReadPublic {
    #[allow(non_camel_case_types)]
    new(Filters, Option<SortOptions>),
    Completed(Responses, Filters, Option<SortOptions>)
}

#[async_trait::async_trait]
impl Command for ReadPublic {
    async fn process<'a>(
        self: Box<Self>, uuid: Uuid, header: Header,
        memory: &mut CompilerMemory, _: &mut CompilerCache
    ) -> Result<Tasks, Error> {
        match *self {
            Self::new(filters, sort_options) => {
                //TODO: I suspect that if sort options contains a field not in the filters it will crash the dwn
                let req = AgentRequest::ReadPublic(filters.clone(), sort_options.clone());
                let callback = move |r: Responses| {Self::Completed(r, filters, sort_options)};
                Task::waiting(uuid, header.clone(), Callback::new(callback), vec![
                    Task::Request(header, req)
                ])
            },
            Self::Completed(mut response, filters, sort_options) => {
                let response = *response.remove(0).downcast::<DwnResponse>()?;
                if let DwnResponse::ReadPublic(mut records) = response {
                    if let Some(sort_options) = sort_options {
                        sort_options.sort(&mut records)?;
                    }
                    let records = futures::future::join_all(records.into_iter().map(|item| async {
                        item.0.verify(memory.did_resolver, None).await.ok()?;
                        if !filters.filter(&item.secondary_keys()) {return None;}
                        let record = item.0.unwrap();
                        record.protocol.validate_payload(&record.payload).ok()?;
                        Some(record)
                    })).await;
                    let records = records.into_iter().flatten().collect::<Vec<_>>();
                    Task::completed(uuid, records)
                } else {Err(Error::bad_response("Expected ReadPublic"))}
            }
        }
    }
}
impl Hashable for ReadPublic {}

#[derive(Serialize, Debug, Clone)]
pub struct UpdatePublic {
    record: PublicRecord,
    signer: Option<Signer>,
}

impl UpdatePublic {
    pub fn new(record: PublicRecord, signer: Option<Signer>) -> Self {
        UpdatePublic{record, signer}
    }
}

#[async_trait::async_trait]
impl Command for UpdatePublic {
    async fn process<'a>(
        self: Box<Self>, uuid: Uuid, header: Header,
        memory: &mut CompilerMemory, _: &mut CompilerCache
    ) -> Result<Tasks, Error> {
        self.record.protocol.validate_payload(&self.record.payload)?;
        let signer = self.signer.unwrap_or(memory.signer());
        let req = MutableAgentRequest::update_public(self.record, signer)?;
        Task::waiting(uuid, header.clone(), Callback::new(EnsureEmpty::new), vec![
            Task::MutableRequest(header, req, 0)
        ])
    }
}
impl Hashable for UpdatePublic {}

#[derive(Serialize, Debug, Clone)]
pub struct DeletePublic {
    uuid: Uuid,
    signer: Option<Signer>
}

impl DeletePublic {
    pub fn new(uuid: Uuid, signer: Option<Signer>) -> Self {
        DeletePublic{uuid, signer}
    }
}

#[async_trait::async_trait]
impl Command for DeletePublic {
    async fn process<'a>(
        self: Box<Self>, uuid: Uuid, header: Header,
        memory: &mut CompilerMemory, _: &mut CompilerCache
    ) -> Result<Tasks, Error> {
        let signer = self.signer.unwrap_or(memory.signer());
        let req = MutableAgentRequest::delete_public(self.uuid, signer)?;
        Task::waiting(uuid, header.clone(), Callback::new(EnsureEmpty::new), vec![
            Task::MutableRequest(header, req, usize::MAX)
        ])
    }
}
impl Hashable for DeletePublic {}
