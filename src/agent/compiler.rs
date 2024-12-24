use super::Error;

use super::protocol::Protocol;
use super::permission::PermissionSet;
use super::traits::Response;
use super::commands::{Complete, Send};
use super::structs::{
    MutableAgentRequest,
    AgentRequest,
    BoxResponse,
    BoxCallback,
    BoxCommand,
    RecordPath,
    PathedKey,
    Responses,
    Callback,
    Header,
    Tasks,
    Task,
};

use crate::dwn::structs::DwnRequest;
use crate::dwn::router::Router;
use crate::dids::{DidResolver, DidKeyPair, Endpoint, Did};
use crate::dids::signing::Signer;

use std::collections::BTreeMap;
use std::sync::Arc;

use simple_crypto::PublicKey;
use uuid::Uuid;

#[derive(Default, Debug)]
pub struct CompilerCache {
    pub record_info: BTreeMap<(Endpoint, bool, RecordPath), (Protocol, PermissionSet)>,
}

#[derive(Debug)]
pub struct CompilerMemory<'a> {
    pub create_index: BTreeMap<(Endpoint, bool, RecordPath), usize>,

    //Readonly
    pub did_resolver: &'a dyn DidResolver,
    sig_key: &'a DidKeyPair,
    enc_key: &'a PathedKey,
    com_key: &'a PathedKey,
    tenant: Did,
}

impl<'a> CompilerMemory<'a> {
    pub fn tenant(&self) -> &Did {&self.tenant}
    pub fn signer(&self) -> Signer {
        Signer::Left(self.sig_key.clone())
    }

    pub fn com_signer(&self) -> Signer {
        Signer::Right(self.com_key.key.clone())
    }

    pub fn get_pub(&self, path: &RecordPath) -> Result<PublicKey, Error> {
        Ok(self.enc_key.derive_path(path.as_slice())?.key.public_key())
    }

    pub fn get_perms(&self, enc: bool, path: &RecordPath, protocol: Option<&Protocol>) -> Result<PermissionSet, Error> {
        let key = if enc {self.enc_key} else {self.com_key};
        key.get_perms(path, protocol)
    }
    pub fn com_decrypt(&self, payload: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(self.com_key.key.decrypt(payload)?)
    }
}

pub type MutableRequestPayload = (Uuid, Header, MutableAgentRequest, usize);
pub type WaitingPayload = (Uuid, Header, BoxCallback, Vec<Uuid>);

pub struct Compiler<'a> {
    original_requests: Option<Vec<Uuid>>,

    ready: Option<Vec<(Uuid, Header, BoxCommand)>>,
    requests: Option<Vec<(Uuid, Header, AgentRequest)>>,
    mutable_requests: Option<Vec<MutableRequestPayload>>,
    waiting: Option<Vec<WaitingPayload>>,

    completed: Option<BTreeMap<Uuid, BoxResponse>>,

    router: &'a Router,

    memory: CompilerMemory<'a>,
    cache: &'a mut CompilerCache
}

impl<'a> Compiler<'a> {
    pub fn new(
        cache: &'a mut CompilerCache,
        did_resolver: &'a dyn DidResolver,
        //protocols: Protocols<'a>,
        sig_key: &'a DidKeyPair,
        enc_key: &'a PathedKey,
        com_key: &'a PathedKey,
        router: &'a Router,
        tenant: Did
    ) -> Self {
        Compiler{
            original_requests: Some(Vec::new()),
            ready: Some(Vec::new()),
            requests: Some(Vec::new()),
            mutable_requests: Some(Vec::new()),
            waiting: Some(Vec::new()),
            completed: Some(BTreeMap::default()),
            router,
            memory: CompilerMemory {
                create_index: BTreeMap::default(),
                did_resolver,
                sig_key,
                enc_key,
                com_key,
                tenant,
            },
            cache
        }
    }

    pub async fn add_command(&mut self, command: BoxCommand, dids: Option<Vec<Did>>) -> Result<(), Error> {
        let dids = dids.unwrap_or(vec![self.memory.tenant().clone()]);
        let id = Uuid::new_v4();
        let order = self.original_requests.as_ref().unwrap().len();
        self.original_requests.as_mut().unwrap().push(id);
        let header = Header::new(id, Endpoint::default(), order, true);

        self.add_tasks(Task::waiting(id, header.clone(), Callback::new(Complete::new_first), vec![
            Task::ready(header, Send::New(command, dids))
        ])?);
        Ok(())
    }


  //fn print(&self) {
  //    println!("Printing---------------------------------------");
  //    println!("Ready: {:#?}", self.ready.as_ref().unwrap().iter().map(|(uuid, ep, v)|
  //        (uuid, ep, (**v).debug(50))
  //    ).collect::<Vec<_>>());
  //    println!("Waiting: {:#?}", BTreeMap::from_iter(self.waiting.as_ref().unwrap().iter().map(|(uuid, _, _, ids)|
  //        (uuid, ids.iter().map(|ouuid| format!("{}: {}", ouuid, self.what_is(ouuid))).collect::<Vec<_>>())
  //    )));
  //    println!("Requests: {:#?}", self.requests.as_ref().unwrap().iter().map(|(uuid, ep, req)|
  //        (uuid, ep, req.truncate_debug(50))
  //    ).collect::<Vec<_>>());
  //     println!("Mutable Requests: {:#?}", self.mutable_requests.as_ref().unwrap().iter().map(|(uuid, ep, req, pri)|
  //        (uuid, ep, req.get_id(), req, pri)
  //    ).collect::<Vec<_>>());

  //    println!("Completed: {:#?}", self.completed.as_ref().unwrap().iter().map(|(uuid, res)|
  //        (uuid, res.debug(50))
  //    ).collect::<Vec<_>>());
  //}

  //fn what_is(&self, uuid: &Uuid) -> String {
  //    if let Some((_, _, v)) = self.ready.as_ref().unwrap().iter().find(|(id, _, _)| id == uuid) {
  //        return (**v).debug(40);
  //    }
  //    if self.waiting.as_ref().unwrap().iter().any(|(id, _, _, _)| id == uuid) {
  //        return "Waiting".to_string();
  //    }
  //    if self.requests.as_ref().unwrap().iter().any(|(id, _, _)| id == uuid) {
  //        return "Request".to_string();
  //    }
  //    if self.mutable_requests.as_ref().unwrap().iter().any(|(id, _, _, _)| id == uuid) {
  //        return "Mutable Request".to_string();
  //    }
  //    if self.completed.as_ref().unwrap().iter().any(|(id, _)| id == uuid) {
  //        return "completed".to_string();
  //    }
  //    panic!("unknown uuid found {}", uuid)
  //}

    fn add_ready(&mut self, uuid: Uuid, header: Header, command: BoxCommand) {
        let hash = command.serialize();
        match self.ready.as_ref().unwrap().iter().find_map(|(ou, oheader, oc)| {
            if header.endpoint == oheader.endpoint && header.enc == oheader.enc && oc.serialize() == hash {Some(ou)} else {None}
        }) {
            Some(ou) => {
                self.wait_on(uuid, header, *ou);
            },
            None => {self.ready.as_mut().unwrap().push((uuid, header, command));}
        }
    }

    fn wait_on(&mut self, uuid: Uuid, header: Header, ouid: Uuid) {
        self.waiting.as_mut().unwrap().push((uuid, header, Callback::new(Complete::new_first), vec![ouid]));
    }

    fn add_tasks(&mut self, tasks: Tasks) {
        for (uuid, task) in tasks {
            match task {
                Task::Ready(header, command) => self.add_ready(uuid, header, command),
                Task::Request(header, request) => {self.requests.as_mut().unwrap().push((uuid, header, request));},
                Task::MutableRequest(header, request, prio) => {self.mutable_requests.as_mut().unwrap().push((uuid, header, request, prio));},
                Task::Waiting(header, callback, ids) => {self.waiting.as_mut().unwrap().push((uuid, header, callback, ids));},
                Task::Completed(completed) => {self.completed.as_mut().unwrap().insert(uuid, completed);},
            }
        }
    }

    async fn process_ready(&mut self) {
        while !self.ready.as_ref().unwrap().is_empty() {
            for org_uuid in self.original_requests.clone().unwrap() {
                while let Some(index) = self.ready.as_ref().unwrap().iter().position(|r| r.1.oid == org_uuid) {
                    let (uuid, header, command) = self.ready.as_mut().unwrap().remove(index);
                    match command.process(uuid, header, &mut self.memory, self.cache).await {
                        Ok(tasks) => self.add_tasks(tasks),
                        Err(e) => {self.completed.as_mut().unwrap().insert(uuid, Box::new(Arc::new(e)));}
                    }
                }
            }
        }
    }

    async fn process_waiting(&mut self) {
        loop {
            let waiting = self.waiting.replace(Default::default()).unwrap().into_iter().flat_map(|(uuid, header, callback, ids)| {
                if ids.iter().all(|id| self.completed.as_ref().unwrap().contains_key(id)) {
                    let responses: Responses = ids.iter().map(|id| {
                        self.completed.as_ref().unwrap().get(id).unwrap().clone()
                    }).collect();
                    if responses.iter().any(|r| r.downcast_ref::<Arc<Error>>().is_some()) {
                        let errors: Vec<Box<Arc<Error>>> = responses.into_iter().flat_map(|r| r.downcast::<Arc<Error>>().ok()).collect();
                        let error = Error::multi(errors);
                        self.completed.as_mut().unwrap().insert(uuid, Box::new(Arc::new(error)));
                    } else {
                        self.add_ready(uuid, header, callback(responses));
                    }
                    None
                } else {Some((uuid, header, callback, ids))}
            }).collect::<Vec<_>>();
            self.waiting.as_mut().unwrap().extend(waiting);

            self.completed = Some(BTreeMap::from_iter(self.completed.take().unwrap().into_iter().flat_map(|(uuid, res)| {
                if self.waiting.as_ref().unwrap().iter().any(|(_, _, _, ids)| ids.contains(&uuid)) ||
                    self.original_requests.as_ref().unwrap().contains(&uuid) {
                    Some((uuid, res))
                } else {None}
            })));
            if !self.waiting.as_ref().unwrap().iter().any(|(_, _, _, ids)| ids.iter().all(|id| self.completed.as_ref().unwrap().contains_key(id))) {break;}
        }
    }

    async fn process_requests(&mut self) {
        let mut requests: BTreeMap<Endpoint, Vec<(Uuid, Box<DwnRequest>)>> = BTreeMap::new();
        let keys: Vec<(Endpoint, Uuid)> = (0..self.requests.as_ref().unwrap().len()).flat_map(|_| {
            let (uuid, header, req) = self.requests.as_mut().unwrap().remove(0);
            if let Some(ouid) = self.requests.as_ref().unwrap().iter().find_map(|(ouid, oheader, oreq)| Some(ouid).filter(|_| header.enc == oheader.enc && header.endpoint == oheader.endpoint && req == *oreq)) {
                self.wait_on(uuid, header, *ouid);
                None
            } else {
                let val = (uuid, Box::new(req.into_dwn_request().unwrap()));
                match requests.get_mut(&header.endpoint) {
                    Some(ep_vec) => {ep_vec.push(val);},
                    None => {requests.insert(header.endpoint.clone(), vec![val]);}
                }
                Some((header.endpoint, uuid))
            }
        }).collect::<Vec<_>>();

        let responses: Vec<(Uuid, BoxResponse)> = match self.router.send(requests).await {
            Err(e) => {
                let error = Box::new(Arc::new(e)) as BoxResponse;
                keys.into_iter().map(|(_, id)| (id, error.clone())).collect()
            },
            Ok(mut resps) => keys.into_iter().map(|(ep, uuid)|
                (uuid, Box::new(resps.get_mut(&ep).unwrap().remove(&uuid).unwrap()) as BoxResponse)
            ).collect()
        };

        self.completed.as_mut().unwrap().extend(responses);
    }

    async fn process_mutable_requests(&mut self) {
        let mut requests: BTreeMap<(Endpoint, Uuid), (Uuid, MutableAgentRequest, usize)> = BTreeMap::new();
         for _ in 0..self.mutable_requests.as_ref().unwrap().len() {
            let (uuid, header, req, prio) = self.mutable_requests.as_mut().unwrap().remove(0);
            let key = (header.endpoint.clone(), req.get_id());
            if let Some((ouid, _, oprio)) = requests.get(&key) {
                if prio > *oprio {
                    self.completed.as_mut().unwrap().insert(*ouid, Box::new(()) as BoxResponse);
                    requests.remove(&key);
                    requests.insert(key, (uuid, req, prio));
                } else {
                    self.completed.as_mut().unwrap().insert(uuid, Box::new(()) as BoxResponse);
                }
            } else {
                requests.insert(key.clone(), (uuid, req, prio));
            }
        }

        let mut ep_requests: BTreeMap<Endpoint, Vec<(Uuid, Box<DwnRequest>)>> = BTreeMap::new();

        let keys = requests.into_iter().map(|((ep, _), (uuid, req, _))| {
            let val = (uuid, Box::new(req.into_dwn_request().unwrap()));
            match ep_requests.get_mut(&ep) {
                Some(ep_vec) => {ep_vec.push(val);},
                None => {ep_requests.insert(ep.clone(), vec![val]);}
            }
            (ep, uuid)
        }).collect::<Vec<_>>();


        let responses: Vec<(Uuid, BoxResponse)> = match self.router.send(ep_requests).await {
            Err(e) => {
                let error = Box::new(Arc::new(e)) as BoxResponse;
                keys.into_iter().map(|(_, id)| (id, error.clone())).collect()
            },
            Ok(mut resps) => keys.into_iter().map(|(ep, uuid)|
                (uuid, Box::new(resps.get_mut(&ep).unwrap().remove(&uuid).unwrap()) as BoxResponse)
            ).collect()
        };
        self.completed.as_mut().unwrap().extend(responses);
    }

    pub async fn compile<'b>(mut self) -> Vec<Vec<Box<dyn Response + 'static>>> {
        loop {
            self.process_ready().await;
            self.process_waiting().await;
            if self.ready.as_ref().unwrap().is_empty() {
                if !self.requests.as_ref().unwrap().is_empty() {
                    self.process_requests().await;
                } else if !self.mutable_requests.as_ref().unwrap().is_empty() {
                    self.process_mutable_requests().await;
                } else {
                    break;
                }
                self.process_waiting().await;
            }
        }
        let mut responses = self.completed.replace(Default::default()).unwrap();
        self.original_requests.replace(Default::default()).unwrap().into_iter().map(|uuid| {
            *responses.remove(&uuid).unwrap().downcast::<Vec<Box<dyn Response>>>().unwrap()
        }).collect()
    }
}
