use super::Error;

use super::compiler::CompilerMemory;
use super::permission::PermissionOptions;
use super::traits::Command;
use super::structs::{
    PrivateRecord,
    AgentRequest,
    RecordInfo,
    RecordPath,
    Responses,
    Callback,
    Record,
    Tasks,
    Task,
};
use super::commands;

use crate::dids::Endpoint;
use crate::dids::signing::Signer;
use crate::dwn::structs::{DwnResponse, PublicRecord};

use simple_database::database::{Filters, SortOptions, Index};
use simple_database::Indexable;

use serde::Serialize;
use uuid::Uuid;

#[derive(Serialize, Clone, Debug)]
pub enum CreatePrivate<'a> {
    #[allow(non_camel_case_types)]
    new(Record, Option<&'a PermissionOptions>),
    GetIndex(Responses, Record, Option<&'a PermissionOptions>),
    CreateRecord(Responses, Record, Option<&'a PermissionOptions>, Box<RecordInfo>),
}

#[async_trait::async_trait]
impl<'a> Command<'a> for CreatePrivate<'a> {
    async fn process(
        self: Box<Self>, uuid: Uuid, ep: Endpoint, mem: &mut CompilerMemory<'a>
    ) -> Result<Tasks<'a>, Error> {
        match *self {
            Self::new(record, p_opts) => {
                let path = record.path.clone();
                let parent_path = path.parent()?;

                let callback = move |r: Responses| {
                    Self::GetIndex(r, record, p_opts)
                };
                Task::waiting(uuid, ep.clone(), Callback::new(callback), vec![
                    Task::ready(ep.clone(), commands::ReadInfo::new(
                        parent_path.clone(), PermissionOptions::create_child()
                    )),
                    Task::ready(ep.clone(), commands::ReadIndex::new(parent_path)),
                    Task::ready(ep, commands::Exists::path(path)),
                ])
            },
            Self::GetIndex(mut results, record, p_opts) => {
                if *results.remove(2).downcast::<bool>()? {
                    //TODO: Check if record is identical return conflict if otherwise
                    return Task::completed(uuid, ());
                }
                let index = *results.remove(1).downcast::<usize>()?;
                let info = *results.remove(0).downcast::<RecordInfo>()?;

                let discover_child = info.1.discover_child()?;

                let callback = move |r: Responses| {
                    Self::CreateRecord(r, record, p_opts, Box::new(info))
                };
                Task::waiting(uuid, ep.clone(), Callback::new(callback), vec![
                    Task::ready(ep, commands::NextIndex::new(discover_child, index, None)),
                ])
            },
            Self::CreateRecord(mut results, record, p_opts, info) => {
                let index = *results.remove(0).downcast::<usize>()?;

                //Validate Parent Child
                let parent_protocol = &info.0;
                parent_protocol.validate_child(&record.protocol)?;

                let (min_perms, req) = commands::CreatePrivate::create(ep.clone(), mem, record, p_opts)?;
                let (i_req, c_req) = commands::CreatePrivate::create_child(ep.clone(), mem, &info.1, &min_perms, index)?;

                Task::waiting(uuid, ep.clone(), Callback::new(commands::EnsureEmpty::new), vec![
                    Task::Request(ep.clone(), i_req),
                    Task::Request(ep.clone(), c_req),
                    Task::Request(ep, req),
                ])
            }
        }
    }
}


#[derive(Serialize, Debug, Clone)]
pub enum ReadPrivate {
    #[allow(non_camel_case_types)]
    new(RecordPath),
    #[allow(non_camel_case_types)]
    child(RecordPath, usize),
    Complete(Responses),
}

#[async_trait::async_trait]
impl<'a> Command<'a> for ReadPrivate {
    async fn process(
        self: Box<Self>, uuid: Uuid, ep: Endpoint, _: &mut CompilerMemory<'a>
    ) -> Result<Tasks<'a>, Error> {
        match *self {
            Self::new(path) => {
                Task::waiting(uuid, ep.clone(), Callback::new(Self::Complete), vec![
                    Task::ready(ep, commands::ReadPrivate::path(path))
                ])
            },
            Self::child(path, index) => {
                Task::waiting(uuid, ep.clone(), Callback::new(Self::Complete), vec![
                    Task::ready(ep, commands::ReadPrivate::child(path, index))
                ])
            },
            Self::Complete(mut results) => {
                let pr = results.remove(0).downcast::<Option<Box<PrivateRecord>>>()?;
                Task::completed(uuid, pr.map(|pr| (*pr).into_record()))
            },
        }
    }
}

#[derive(Serialize, Debug, Clone)]
pub enum UpdatePrivate<'a> {
    #[allow(non_camel_case_types)]
    new(Record, Option<&'a PermissionOptions>),
    UpdateOrCreate(Responses, Record, Option<&'a PermissionOptions>),
}

#[async_trait::async_trait]
impl<'a> Command<'a> for UpdatePrivate<'a> {
    async fn process(
        self: Box<Self>, uuid: Uuid, ep: Endpoint, mem: &mut CompilerMemory<'a>
    ) -> Result<Tasks<'a>, Error> {
        match *self {
            Self::new(record, p_opts) => {
                let parent_path = record.path.parent()?;
                let record_path = record.path.clone();
                let callback = move |r: Responses| {Self::UpdateOrCreate(r, record, p_opts)};
                Task::waiting(uuid, ep.clone(), Callback::new(callback), vec![
                    Task::ready(ep.clone(), commands::ReadInfo::new(
                        parent_path.clone(), PermissionOptions::create_child()
                    )),
                    Task::ready(ep.clone(), commands::ReadIndex::new(parent_path)),
                    Task::ready(ep, commands::ReadPrivate::path(record_path)),
                ])
            },
            Self::UpdateOrCreate(mut r, record, p_opts) => {
                match *r.remove(2).downcast::<Option<Box<PrivateRecord>>>()? {
                    Some(e_record) => {
                        let protocol = mem.get_protocol(&record.protocol)?;
                        let perms = e_record.perms;
                        let req = AgentRequest::update_private(0, perms.clone(), p_opts, protocol, record.payload)?;
                        Task::waiting(uuid, ep.clone(), Callback::new(commands::EnsureEmpty::new),
                            vec![Task::Request(ep, req)]
                        )
                    },
                    None => {
                        r.insert(2, Box::new(false));
                        Task::next(uuid, ep,  CreatePrivate::GetIndex(r, record, p_opts))
                    }
                }
            },
        }
    }
}

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
impl<'a> Command<'a> for DeletePrivate {
    async fn process(
        self: Box<Self>, uuid: Uuid, ep: Endpoint, mem: &mut CompilerMemory<'a>
    ) -> Result<Tasks<'a>, Error> {
        let perms = mem.key.get_perms(&self.path, None)?;
        Task::waiting(uuid, ep.clone(), Callback::new(commands::EnsureEmpty::new), vec![
            Task::Request(ep, AgentRequest::delete_private(0, &perms)?)
        ])
    }
}

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
impl<'a> Command<'a> for CreatePublic {
    async fn process(
        self: Box<Self>, uuid: Uuid, ep: Endpoint, mem: &mut CompilerMemory<'a>
    ) -> Result<Tasks<'a>, Error> {
        let protocol = mem.get_protocol(&self.record.protocol)?;
        protocol.validate_payload(&self.record.payload)?;
        let signer = self.signer.unwrap_or(Signer::Left(mem.sig_key.clone()));
        Task::waiting(uuid, ep.clone(), Callback::new(commands::EnsureEmpty::new), vec![
            Task::Request(ep, AgentRequest::create_public(0, self.record, signer)?)
        ])
    }
}

#[derive(Serialize, Debug, Clone)]
pub enum ReadPublic {
    #[allow(non_camel_case_types)]
    new(Filters, Option<SortOptions>),
    Completed(Responses, Filters, Option<SortOptions>)
}

#[async_trait::async_trait]
impl<'a> Command<'a> for ReadPublic {
    async fn process(
        self: Box<Self>, uuid: Uuid, ep: Endpoint, mem: &mut CompilerMemory<'a>
    ) -> Result<Tasks<'a>, Error> {
        match *self {
            Self::new(filters, sort_options) => {
                //TODO: I suspect that if sort options contains a field not in the filters it will crash the dwn
                let req = AgentRequest::read_public(filters.clone(), sort_options.clone())?;
                let callback = move |r: Responses| {Self::Completed(r, filters, sort_options)};
                Task::waiting(uuid, ep.clone(), Callback::new(callback), vec![
                    Task::Request(ep, req)
                ])
            },
            Self::Completed(mut response, filters, sort_options) => {
                let response = *response.remove(0).downcast::<DwnResponse>()?;
                if let DwnResponse::ReadPublic(mut records) = response {
                    if let Some(sort_options) = sort_options {
                        sort_options.sort(&mut records)?;
                    }
                    let records = futures::future::join_all(records.into_iter().map(|item| async {
                        item.0.verify(mem.did_resolver, None).await.ok()?;
                        if !filters.filter(&item.secondary_keys()) {return None;}
                        let record = item.0.unwrap();
                        let protocol = mem.get_protocol(&record.protocol).ok()?;
                        protocol.validate_payload(&record.payload).ok()?;
                        Some(record)
                    })).await;
                    let records = records.into_iter().flatten().collect::<Vec<_>>();
                    Task::completed(uuid, records)
                } else {Err(Error::bad_response("Expected ReadPublic"))}
            }
        }
    }
}

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
impl<'a> Command<'a> for UpdatePublic {
    async fn process(
        self: Box<Self>, uuid: Uuid, ep: Endpoint, mem: &mut CompilerMemory<'a>
    ) -> Result<Tasks<'a>, Error> {
        let protocol = mem.get_protocol(&self.record.protocol)?;
        protocol.validate_payload(&self.record.payload)?;
        let signer = self.signer.unwrap_or(Signer::Left(mem.sig_key.clone()));
        Task::waiting(uuid, ep.clone(), Callback::new(commands::EnsureEmpty::new), vec![
            Task::Request(ep, AgentRequest::update_public(0, self.record, signer)?)
        ])
    }
}

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
impl<'a> Command<'a> for DeletePublic {
    async fn process(
        self: Box<Self>, uuid: Uuid, ep: Endpoint, mem: &mut CompilerMemory<'a>
    ) -> Result<Tasks<'a>, Error> {
        let signer = self.signer.unwrap_or(Signer::Left(mem.sig_key.clone()));
        Task::waiting(uuid, ep.clone(), Callback::new(commands::EnsureEmpty::new), vec![
            Task::Request(ep, AgentRequest::delete_public(0, self.uuid, signer)?)
        ])
    }
}

#[derive(Serialize, Debug, Clone)]
pub enum Scan {
    #[allow(non_camel_case_types)]
    new(RecordPath, usize),
    Completed(Responses),
}

#[async_trait::async_trait]
impl<'a> Command<'a> for Scan {
    async fn process(
        self: Box<Self>, uuid: Uuid, ep: Endpoint, _: &mut CompilerMemory
    ) -> Result<Tasks<'a>, Error> {
        match *self {
            Self::new(path, start) => {
                Task::waiting(uuid, ep.clone(), Callback::new(Self::Completed), vec![
                    Task::ready(ep, commands::Scan::new(path, start))
                ])
            },
            Self::Completed(mut responses) => {
                let records = *responses.remove(0).downcast::<Vec<PrivateRecord>>()?;
                Task::completed(uuid,
                    records.into_iter().map(|pr| pr.into_record()).collect::<Vec<_>>()
                )
            }
        }
    }
}
