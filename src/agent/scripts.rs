use super::Error;

use super::compiler::{CompilerMemory, CompilerCache};
use super::permission::PermissionOptions;
use super::traits::Command;
use super::structs::{
    MutableAgentRequest,
    PrivateRecord,
    AgentRequest,
    RecordInfo,
    RecordPath,
    Responses,
    Callback,
    Header,
    Record,
    Tasks,
    Task,
};
use super::commands;

use crate::dids::signing::Signer;
use crate::dwn::structs::{DwnResponse, PublicRecord};

use simple_database::database::{Filters, SortOptions};
use simple_database::Indexable;

use uuid::Uuid;

#[derive(Clone, Debug)]
pub enum CreatePrivate<'a> {
    #[allow(non_camel_case_types)]
    new(Record, Option<&'a PermissionOptions>),
    GetIndex(Responses, Record, Option<&'a PermissionOptions>),
    CreateRecord(Responses, Record, Option<&'a PermissionOptions>, Box<RecordInfo>),
}

#[async_trait::async_trait]
impl<'a> Command<'a> for CreatePrivate<'a> {
    async fn process(
        self: Box<Self>, uuid: Uuid, header: Header,
        memory: &mut CompilerMemory<'a>, cache: &mut CompilerCache
    ) -> Result<Tasks<'a>, Error> {
        match *self {
            Self::new(record, p_opts) => {
                let record_path = record.path.clone();
                let parent_path = record_path.parent()?;

                let callback = move |r: Responses| {
                    Self::GetIndex(r, record, p_opts)
                };
                Task::waiting(uuid, header.clone(), Callback::new(callback), vec![
                    Task::ready(header.clone(), commands::ReadInfo::new(
                        parent_path.clone(), PermissionOptions::create_child()
                    )),
                    Task::ready(header.clone(), commands::ReadIndex::new(parent_path)),
                    Task::ready(header, commands::ReadPrivate::path(record_path)),
                ])
            },
            Self::GetIndex(mut results, record, p_opts) => {
                match *results.remove(2).downcast::<(Option<Box<PrivateRecord>>, bool)>()? {
                    (Some(precord), true) if precord.clone().into_record() == record => {
                        return Task::completed(uuid, ());
                    },
                    (_, true) => {return Task::completed(uuid, "Conflict");},
                    _ => {}
                }
                let index = *results.remove(1).downcast::<usize>()?;
                let info = *results.remove(0).downcast::<RecordInfo>()?;

                let discover_child = info.1.discover_child()?;

                let callback = move |r: Responses| {
                    Self::CreateRecord(r, record, p_opts, Box::new(info))
                };
                Task::waiting(uuid, header.clone(), Callback::new(callback), vec![
                    Task::ready(header, commands::NextIndex::new(discover_child, index, None)),
                ])
            },
            Self::CreateRecord(mut results, record, p_opts, info) => {
                let index = *results.remove(0).downcast::<usize>()?;

                //Validate Parent Child
                let parent_protocol = &info.0;
                parent_protocol.validate_child(&record.protocol)?;

                let (min_perms, req) = commands::CreatePrivate::create(header.clone(), memory, cache, record, p_opts)?;
                let (i_req, c_req, index) = commands::CreatePrivate::create_child(header.clone(), memory, &info.1, &min_perms, index)?;

                Task::waiting(uuid, header.clone(), Callback::new(commands::EnsureEmpty::new), vec![
                    Task::MutableRequest(header.clone(), i_req, index),
                    Task::MutableRequest(header.clone(), c_req, 0),
                    Task::MutableRequest(header, req, 0),
                ])
            }
        }
    }
}


#[derive(Debug, Clone)]
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
        self: Box<Self>, uuid: Uuid, header: Header,
        _: &mut CompilerMemory<'a>, _: &mut CompilerCache
    ) -> Result<Tasks<'a>, Error> {
        match *self {
            Self::new(path) => {
                Task::waiting(uuid, header.clone(), Callback::new(Self::Complete), vec![
                    Task::ready(header, commands::ReadPrivate::path(path))
                ])
            },
            Self::child(path, index) => {
                Task::waiting(uuid, header.clone(), Callback::new(Self::Complete), vec![
                    Task::ready(header, commands::ReadPrivate::child(path, index))
                ])
            },
            Self::Complete(mut results) => {
                let pr = results.remove(0).downcast::<(Option<Box<PrivateRecord>>, bool)>()?.0;
                Task::completed(uuid, pr.map(|pr| (*pr).into_record()))
            },
        }
    }
}

#[derive(Debug, Clone)]
pub enum UpdatePrivate<'a> {
    #[allow(non_camel_case_types)]
    new(Record, Option<&'a PermissionOptions>),
    UpdateOrCreate(Responses, Record, Option<&'a PermissionOptions>),
}

#[async_trait::async_trait]
impl<'a> Command<'a> for UpdatePrivate<'a> {
    async fn process(
        self: Box<Self>, uuid: Uuid, header: Header,
        memory: &mut CompilerMemory<'a>, _: &mut CompilerCache
    ) -> Result<Tasks<'a>, Error> {
        match *self {
            Self::new(record, p_opts) => {
                let parent_path = record.path.parent()?;
                let record_path = record.path.clone();
                let callback = move |r: Responses| {Self::UpdateOrCreate(r, record, p_opts)};
                Task::waiting(uuid, header.clone(), Callback::new(callback), vec![
                    Task::ready(header.clone(), commands::ReadInfo::new(
                        parent_path.clone(), PermissionOptions::create_child()
                    )),
                    Task::ready(header.clone(), commands::ReadIndex::new(parent_path)),
                    Task::ready(header, commands::ReadPrivate::path(record_path)),
                ])
            },
            Self::UpdateOrCreate(mut r, record, p_opts) => {
                match *r.remove(2).downcast::<(Option<Box<PrivateRecord>>, bool)>()? {
                    (Some(e_record), _) => {
                        let protocol = memory.get_protocol(&record.protocol)?;
                        let perms = e_record.perms;
                        let req = MutableAgentRequest::update_private(perms.clone(), p_opts, protocol, record.payload)?;
                        let order = header.2;
                        Task::waiting(uuid, header.clone(), Callback::new(commands::EnsureEmpty::new),
                            vec![Task::MutableRequest(header, req, order)]
                        )
                    },
                    (None, exists) => {
                        r.insert(2, Box::new((None::<Box<PrivateRecord>>, exists)));
                        Task::next(uuid, header,  CreatePrivate::GetIndex(r, record, p_opts))
                    }
                }
            },
        }
    }
}

#[derive(Debug, Clone)]
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
        self: Box<Self>, uuid: Uuid, header: Header,
        memory: &mut CompilerMemory<'a>, _: &mut CompilerCache
    ) -> Result<Tasks<'a>, Error> {
        let perms = memory.key.get_perms(&self.path, None)?;
        let req = MutableAgentRequest::delete_private(&perms)?;
        Task::waiting(uuid, header.clone(), Callback::new(commands::EnsureEmpty::new), vec![
            Task::MutableRequest(header, req, usize::MAX)
        ])
    }
}

#[derive(Debug, Clone)]
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
        self: Box<Self>, uuid: Uuid, header: Header,
        memory: &mut CompilerMemory<'a>, _: &mut CompilerCache
    ) -> Result<Tasks<'a>, Error> {
        let protocol = memory.get_protocol(&self.record.protocol)?;
        protocol.validate_payload(&self.record.payload)?;
        let signer = self.signer.unwrap_or(Signer::Left(memory.sig_key.clone()));
        let req = MutableAgentRequest::create_public(self.record, signer)?;
        Task::waiting(uuid, header.clone(), Callback::new(commands::EnsureEmpty::new), vec![
            Task::MutableRequest(header, req, 0)
        ])
    }
}

#[derive(Debug, Clone)]
pub enum ReadPublic {
    #[allow(non_camel_case_types)]
    new(Filters, Option<SortOptions>),
    Completed(Responses, Filters, Option<SortOptions>)
}

#[async_trait::async_trait]
impl<'a> Command<'a> for ReadPublic {
    async fn process(
        self: Box<Self>, uuid: Uuid, header: Header,
        memory: &mut CompilerMemory<'a>, _: &mut CompilerCache
    ) -> Result<Tasks<'a>, Error> {
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
                        let protocol = memory.get_protocol(&record.protocol).ok()?;
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

#[derive(Debug, Clone)]
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
        self: Box<Self>, uuid: Uuid, header: Header,
        memory: &mut CompilerMemory<'a>, _: &mut CompilerCache
    ) -> Result<Tasks<'a>, Error> {
        let protocol = memory.get_protocol(&self.record.protocol)?;
        protocol.validate_payload(&self.record.payload)?;
        let signer = self.signer.unwrap_or(Signer::Left(memory.sig_key.clone()));
        let req = MutableAgentRequest::update_public(self.record, signer)?;
        Task::waiting(uuid, header.clone(), Callback::new(commands::EnsureEmpty::new), vec![
            Task::MutableRequest(header, req, 0)
        ])
    }
}

#[derive(Debug, Clone)]
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
        self: Box<Self>, uuid: Uuid, header: Header,
        memory: &mut CompilerMemory<'a>, _: &mut CompilerCache
    ) -> Result<Tasks<'a>, Error> {
        let signer = self.signer.unwrap_or(Signer::Left(memory.sig_key.clone()));
        let req = MutableAgentRequest::delete_public(self.uuid, signer)?;
        Task::waiting(uuid, header.clone(), Callback::new(commands::EnsureEmpty::new), vec![
            Task::MutableRequest(header, req, usize::MAX)
        ])
    }
}

#[derive(Debug, Clone)]
pub enum Scan {
    #[allow(non_camel_case_types)]
    new(RecordPath, usize),
    Completed(Responses),
}

#[async_trait::async_trait]
impl<'a> Command<'a> for Scan {
    async fn process(
        self: Box<Self>, uuid: Uuid, header: Header,
        _: &mut CompilerMemory<'a>, _: &mut CompilerCache
    ) -> Result<Tasks<'a>, Error> {
        match *self {
            Self::new(path, start) => {
                Task::waiting(uuid, header.clone(), Callback::new(Self::Completed), vec![
                    Task::ready(header, commands::Scan::new(path, start))
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
