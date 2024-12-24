use super::Error;

use super::compiler::{CompilerMemory, CompilerCache};
use super::permission::PermissionOptions;
use super::traits::Command;
use super::structs::{
    PrivateRecord,
    BoxCommand,
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
use crate::dids::Did;
use crate::dwn::structs::PublicRecord;

use std::collections::BTreeMap;

use simple_database::database::{Filters, Filter, SortOptions};
use simple_crypto::PublicKey;

use serde::Serialize;
use uuid::Uuid;

#[derive(Serialize, Debug, Clone)]
pub struct CreatePrivate {}
impl CreatePrivate {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(record: Record, p_opts: Option<PermissionOptions>) -> BoxCommand {
        Box::new(commands::CreatePrivate::new(record, p_opts))
    }
}

#[derive(Serialize, Debug, Clone)]
pub enum ReadPrivate {
    New(RecordPath),
    Child(RecordPath, usize),
    Complete(Responses),
}

impl ReadPrivate {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(path: RecordPath) -> BoxCommand {
        Box::new(ReadPrivate::New(path))
    }

    pub fn child(path: RecordPath, index: usize) -> BoxCommand {
        Box::new(ReadPrivate::Child(path, index))
    }
}

#[async_trait::async_trait]
impl Command for ReadPrivate {
    async fn process<'a>(
        self: Box<Self>, uuid: Uuid, header: Header,
        _: &mut CompilerMemory, _: &mut CompilerCache
    ) -> Result<Tasks, Error> {
        match *self {
            Self::New(path) => {
                Task::waiting(uuid, header.clone(), Callback::new(Self::Complete), vec![
                    Task::ready(header, commands::ReadPrivate::path(path))
                ])
            },
            Self::Child(path, index) => {
                Task::waiting(uuid, header.clone(), Callback::new(Self::Complete), vec![
                    Task::ready(header, commands::ReadPrivateChild::new(path, index))
                ])
            },
            Self::Complete(mut results) => {
                let pr = results.remove(0).downcast::<(Option<Box<PrivateRecord>>, bool)>()?.0;
                Task::completed(uuid, pr.map(|pr| (*pr).into_record()))
            },
        }
    }
}

#[derive(Serialize, Debug, Clone)]
pub struct UpdatePrivate {}

impl UpdatePrivate {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(record: Record, p_opts: Option<PermissionOptions>) -> BoxCommand {
        Box::new(commands::UpdatePrivate::new(record, p_opts))
    }
}

#[derive(Serialize, Debug, Clone)]
pub struct DeletePrivate {}

impl DeletePrivate {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(path: RecordPath) -> BoxCommand {
        Box::new(commands::DeletePrivate::new(path))
    }
}

#[derive(Serialize, Debug, Clone)]
pub struct CreatePublic {}
impl CreatePublic {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(record: PublicRecord, signer: Option<Signer>) -> BoxCommand {
        Box::new(commands::CreatePublic::new(record, signer))
    }
}

#[derive(Serialize, Debug, Clone)]
pub struct ReadPublic {}
impl ReadPublic {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(filters: Filters, sort_options: Option<SortOptions>) -> BoxCommand {
        Box::new(commands::ReadPublic::new(filters, sort_options))
    }
}

#[derive(Serialize, Debug, Clone)]
pub struct UpdatePublic {}
impl UpdatePublic {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(record: PublicRecord, signer: Option<Signer>) -> BoxCommand {
        Box::new(commands::UpdatePublic::new(record, signer))
    }
}

#[derive(Serialize, Debug, Clone)]
pub struct DeletePublic {}
impl DeletePublic {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(uuid: Uuid, signer: Option<Signer>) -> BoxCommand {
        Box::new(commands::DeletePublic::new(uuid, signer))
    }
}

#[derive(Serialize, Debug, Clone)]
pub enum Scan {
    New(RecordPath, usize),
    Completed(Responses),
}

impl Scan {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(path: RecordPath, index: usize) -> BoxCommand {
        Box::new(Scan::New(path, index))
    }
}

#[async_trait::async_trait]
impl Command for Scan {
    async fn process<'a>(
        self: Box<Self>, uuid: Uuid, header: Header,
        _: &mut CompilerMemory, _: &mut CompilerCache
    ) -> Result<Tasks, Error> {
        match *self {
            Self::New(path, start) => {
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

#[derive(Serialize, Debug, Clone)]
pub enum Share {
    New(RecordPath, Option<PermissionOptions>, Did),
    Channel(Responses, RecordPath, Option<PermissionOptions>),
  //Completed(Responses),
}

impl Share {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        path: RecordPath, p_opts: Option<PermissionOptions>, recipient: Did
    ) -> BoxCommand {
        Box::new(Share::New(path, p_opts, recipient))
    }
}

#[async_trait::async_trait]
impl Command for Share {
    async fn process<'a>(
        self: Box<Self>, uuid: Uuid, header: Header,
        memory: &mut CompilerMemory, _: &mut CompilerCache
    ) -> Result<Tasks, Error> {
        match *self {
            Self::New(path, p_opts, recipient) => {
                let filters = Filters::new(vec![
                    ("signer", Filter::equal(recipient.to_string())),
                    ("type", Filter::equal("agent_keys".to_string()))
                ]);

                let path_copy = path.clone();
                let callback = move |r: Responses| {Self::Channel(r, path_copy, p_opts)};
                Task::waiting(uuid, header.clone(), Callback::new(callback), vec![
                    Task::ready(header.clone(), commands::ReadPrivate::path(path)),
                    Task::ready(header.clone(), commands::EstablishChannel::new(recipient.clone())),
                    Task::ready(header, commands::Send::New(ReadPublic::new(filters, None), vec![recipient]))
                ])
            },
            Self::Channel(mut responses, path, p_opts) => {
                let record_resp = *responses.remove(2).downcast::<Responses>()?;
                let _channel = *responses.remove(1).downcast::<()>()?;
                let sharing_record = *responses.remove(0).downcast::<Option<Box<PrivateRecord>>>()?;

                let protocol = sharing_record.ok_or(Error::not_found("Record"))?.protocol;
                let perms = protocol.subset_permission(
                    memory.get_perms(header.enc, &path, Some(&protocol))?, p_opts.as_ref()
                )?;

              //let channel_path = RecordPath::new(&[Uuid::new_v5(
              //    &Uuid::NAMESPACE_OID, recipient.to_string().as_bytes()
              //)]);

                let agent_keys = record_resp.into_iter().find_map(|response|
                    response.downcast::<Vec<PublicRecord>>().ok().and_then(|mut records|
                        records.pop().and_then(|record|
                            serde_json::from_slice::<BTreeMap<RecordPath, PublicKey>>(&record.payload).ok()
                        )
                    )
                ).ok_or(Error::bad_request("Recipient has no active agents"))?;

                let keys = agent_keys.into_iter().flat_map(|(opath, key)|
                    Some(key).filter(|_| opath.parent_of(&path))
                ).collect::<Vec<_>>();
                keys.into_iter().map(|key|
                    Ok(key.encrypt(&serde_json::to_vec(&perms)?)?)
                ).collect::<Result<Vec<Vec<u8>>, Error>>()?;

              //let record = Record::new(channel_path.

              //Task::waiting(uuid, header.com(), Callback::new(EnsureEmpty::new), vec![
              //    Task::Ready(
              //])

                todo!()

              //}
              //let channel = self.establish_direct_messages(recipient).await?;

                            //let perms = serde_json::to_vec(&self.get_permission(path)?.subset(permission_options)?)?;

              //let agent_keys = self.public_read(filters, None, Some(&[recipient])).await?.first().and_then(|(_, record)|
              //    serde_json::from_slice::<Vec<PublicKey>>(&record.payload).ok()
              //).ok_or(Error::bad_request("Agent.share", "Recipient has no agents"))?
              //.into_iter().map(|key| Ok(key.encrypt(&perms)?)).collect::<Result<Vec<Vec<u8>>, Error>>()?;
              //let record = Record::new(None, &SystemProtocols::shared_pointer(), serde_json::to_vec(&agent_keys)?);
              //self.private_client.create_child(
              //    &channel.perms,
              //    record,
              //    None,
              //    &[self.tenant(), recipient]
              //).await?;

              //Task::waiting(uuid, header.clone(), Callback::new(Self::Completed), vec![
              //    Task::ready(header, commands::Scan::new(path, start))
              //])
            },
          //Self::Completed(mut responses) => {
          //    let records = *responses.remove(0).downcast::<Vec<PrivateRecord>>()?;
          //    Task::completed(uuid,
          //        records.into_iter().map(|pr| pr.into_record()).collect::<Vec<_>>()
          //    )
          //}
        }
    }
}

//      let folder_path = RecordPath::new(&[protocol]);
//      let root_agent_key = self.root();

//      let folder_protocol = SystemProtocols::protocol_folder(protocol);
//      let agent = Agent::new(root_agent_key, vec![folder_protocol.clone()], self.did_resolver.clone(), self.client.clone());

//      let record = Record::new(folder_path.clone(), folder_protocol.uuid(), &[]);
//      let filters = Filters::new(vec![
//          ("signer", Filter::equal(self.identity.sig_key.public.did.to_string())),
//          ("type", Filter::equal("agent_keys".to_string()))
//      ]);

//      let mut cache = CompilerCache::default();
//      let mut responses = agent.process_commands(&mut cache, vec![
//          scripts::CreatePrivate::new(record, None),
//          scripts::ReadPublic::new(filters, None)
//      ]).await?;

//      let mut agent_keys = responses.remove(1).downcast::<Vec<Record>>()?.first().and_then(|record|
//          serde_json::from_slice::<Vec<PublicKey>>(&record.payload).ok()
//      ).unwrap_or_default();
//      responses.remove(0).downcast::<()>()?;

//      let enc_key = self.identity.enc_key.derive_path(folder_path.as_slice())?;
//      if !agent_keys.contains(&enc_key.key.public_key()) {
//          agent_keys.push(enc_key.key.public_key());

//          let index = IndexBuilder::build(vec![("type", "agent_keys")])?;
//          let record = PublicRecord::new(None, SystemProtocols::agent_keys().uuid(), &serde_json::to_vec(&agent_keys)?, Some(index))?;
//          agent.process_commands(&mut cache, vec![
//              scripts::UpdatePublic::new(record, None)
//          ]).await?.remove(0).downcast::<()>()?;
//      }
//      Ok(AgentKey{sig_key: self.identity.sig_key.clone(), enc_key, com_key: self.identity.com_key.clone()})
