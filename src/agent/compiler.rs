use super::Error;

use super::protocol::Protocol;
use super::permission::PermissionSet;
use super::traits::{Response, Command};
use super::structs::{
    ErrorWrapper,
    AgentRequest,
    BoxResponse,
    BoxCallback,
    BoxCommand,
    RecordPath,
    Protocols,
    PathedKey,
    Responses,
    Callback,
    Tasks,
    Task,
};

use crate::dwn::structs::DwnRequest;
use crate::dwn::router::Router;
use crate::dids::{DidResolver, DidKeyPair, Endpoint, Did};

use std::collections::BTreeMap;

use simple_crypto::PublicKey;

use serde::Serialize;
use uuid::Uuid;

use super::traits::TypeDebug;

#[derive(Serialize, Debug, Clone)]
struct Complete {
    response: Box<dyn Response>
}
impl Complete {
    pub fn new_first(mut responses: Responses) -> Self {Complete{response: responses.remove(0)}}
    pub fn new(responses: Responses) -> Self {Complete{response: Box::new(responses)}}
}

#[async_trait::async_trait]
impl<'a> Command<'a> for Complete {
    async fn process(mut self: Box<Self>, uuid: Uuid, _: Endpoint, _: &mut CompilerMemory) -> Result<Tasks<'a>, Error> {
        Ok(vec![(uuid, Task::Completed(self.response))])
    }
}

#[derive(Debug)]
pub struct CompilerMemory<'a> {
    pub did_resolver: &'a dyn DidResolver,
    pub record_info: BTreeMap<(Endpoint, RecordPath), (Protocol, PermissionSet)>,
    pub create_index: BTreeMap<(Endpoint, RecordPath), usize>,
    pub protocols: Protocols<'a>,
    pub sig_key: &'a DidKeyPair,
    pub key: &'a PathedKey,
}

impl<'a> CompilerMemory<'a> {
    pub fn get_protocol(&self, protocol: &Uuid) -> Result<&Protocol, Error> {
        self.protocols.get(protocol).ok_or(Error::not_found("Protocol"))
    }
}

pub type WaitPayload<'a> = (Endpoint, BoxCallback<'a>, Vec<Uuid>);

//TODO: Preserve ordering of requests
pub struct Compiler<'a> {
    original_requests: Option<Vec<Uuid>>,
    ready: Option<BTreeMap<Uuid, (Endpoint, BoxCommand<'a>)>>,
    requests: Option<BTreeMap<Uuid, (Endpoint, AgentRequest)>>,
    waiting: Option<BTreeMap<Uuid, WaitPayload<'a>>>,
    completed: Option<BTreeMap<Uuid, BoxResponse>>,

    did_resolver: &'a dyn DidResolver,
    router: &'a Router,
    tenant: Did,

    memory: CompilerMemory<'a>,
}

impl<'a> Compiler<'a> {
    pub fn new(memory: CompilerMemory<'a>, router: &'a Router, did_resolver: &'a dyn DidResolver, tenant: Did) -> Self {
        Compiler{
            original_requests: Some(Vec::new()),
            ready: Some(BTreeMap::default()),
            requests: Some(BTreeMap::default()),
            waiting: Some(BTreeMap::default()),
            completed: Some(BTreeMap::default()),
            did_resolver,
            router,
            tenant,
            memory,
        }
    }

    pub async fn add_command(&mut self, command: impl Command<'a> + 'a + Clone, dids: Option<Vec<Did>>) -> Result<(), Error> {
        let dids = dids.unwrap_or(vec![self.tenant.clone()]);
        let id = Uuid::new_v4();
        self.original_requests.as_mut().unwrap().push(id);
        let endpoints = command.get_endpoints(dids, self.did_resolver).await?;
        let ep = endpoints.first().unwrap().clone();
        let tasks = endpoints.into_iter().map(|ep|
            Task::Ready(ep, Box::new(command.clone()))
        ).collect::<Vec<_>>();
        let tasks = Task::waiting(id, ep, Callback::new(Complete::new), tasks)?;
        self.add_tasks(tasks);
        Ok(())
    }

    fn no_ready_tasks(&self) -> bool {
        self.ready.as_ref().unwrap().is_empty()
    }

    fn no_waiting_tasks(&self) -> bool {
        self.waiting.as_ref().unwrap().is_empty()
    }

    fn no_request_tasks(&self) -> bool {
        self.requests.as_ref().unwrap().is_empty()
    }

  //fn print(&self) {
  //    println!("Printing---------------------------------------");
  //    let test = self.ready.as_ref().unwrap().iter().map(|(uuid, (ep, v))| (uuid, ep, (**v).truncate_debug())).collect::<Vec<_>>();
  //    println!("Ready: {:#?}", test);
  //    println!("Waiting: {:#?}", self.waiting.as_ref().unwrap().iter().map(|(uuid, on)|
  //        (uuid, on.2.iter().map(|ouuid| (ouuid, self.what_is(ouuid))).collect::<Vec<_>>())
  //    ).collect::<Vec<_>>());
  //    println!("Requests: {:#?}", self.requests.as_ref().unwrap().iter().map(|(uuid, (ep, req))| (uuid, ep, req.truncate_debug())).collect::<Vec<_>>());
  //    println!("Completed: {:#?}", self.completed.as_ref().unwrap().iter().map(|(uuid, res)| (uuid, res.truncate_debug())).collect::<Vec<_>>());
  //}

  //fn what_is(&self, uuid: &Uuid) -> String {
  //    if let Some((ep, v)) = self.ready.as_ref().unwrap().get(&uuid) {
  //        return ((**v).truncate_debug());
  //    }
  //    if self.waiting.as_ref().unwrap().get(uuid).is_some() {
  //        return "Waiting".to_string();
  //    }
  //    if self.requests.as_ref().unwrap().get(uuid).is_some() {
  //        return "Request in process".to_string();
  //    }
  //    if self.completed.as_ref().unwrap().get(uuid).is_some() {
  //        return "completed".to_string();
  //    }
  //    panic!("unknown uuid found {}", uuid)
  //}

    pub fn add_ready(&mut self, uuid: Uuid, ep: Endpoint, command: BoxCommand<'a>) {
        let ser_c = command.serialize();
        match self.ready.as_ref().unwrap().iter().find_map(|(ou, (oep, oc))|
            if ep == *oep && oc.serialize() == ser_c {Some(ou)} else {None}
        ) {
            Some(ou) => {
                self.wait_on(uuid, ep, *ou);
            },
            None => {self.ready.as_mut().unwrap().insert(uuid, (ep, command));}
        }
    }

    pub fn wait_on(&mut self, uuid: Uuid, ep: Endpoint, ouid: Uuid) {
        self.waiting.as_mut().unwrap().insert(uuid, (ep, Callback::new(Complete::new_first), vec![ouid]));
    }

    pub fn add_tasks(&mut self, tasks: Tasks<'a>) {
        for (uuid, task) in tasks {
            match task {
                Task::Ready(ep, command) => self.add_ready(uuid, ep, command),
                Task::Request(ep, request) => {self.requests.as_mut().unwrap().insert(uuid, (ep, request));},
                Task::Waiting(ep, callback, ids) => {self.waiting.as_mut().unwrap().insert(uuid, (ep, callback, ids));},
                Task::Completed(completed) => {self.completed.as_mut().unwrap().insert(uuid, completed);},
            }
        }
    }

    pub async fn compile<'b>(mut self) -> (Vec<Vec<Box<dyn Response + 'static>>>, CompilerMemory<'a>) {
        loop {
            //self.print();
            for (uuid, (ep, command)) in self.ready.replace(Default::default()).unwrap() {
                match command.process(uuid, ep, &mut self.memory).await {
                    Ok(tasks) => self.add_tasks(tasks),
                    Err(e) => {self.completed.as_mut().unwrap().insert(uuid, Box::new(ErrorWrapper::new(e)));}
                }
            };
            if self.no_ready_tasks() {
                self.waiting = Some(BTreeMap::from_iter(self.waiting.take().unwrap().into_iter().flat_map(|(uuid, (ep, callback, ids))| {
                        if ids.iter().all(|id| self.completed.as_ref().unwrap().contains_key(id)) {
                            let responses: Responses = ids.iter().map(|id| {
                                self.completed.as_ref().unwrap().get(id).unwrap().clone()
                            }).collect();
                            if responses.iter().any(|r| r.downcast_ref::<ErrorWrapper>().is_some()) {
                                let errors: Vec<Box<ErrorWrapper>> = responses.into_iter().flat_map(|r| r.downcast::<ErrorWrapper>().ok()).collect();
                                let error = Error::multi(errors);
                                self.completed.as_mut().unwrap().insert(uuid, Box::new(ErrorWrapper::new(error)));
                            } else {
                                self.ready.as_mut().unwrap().insert(uuid, (ep, callback(responses)));
                            }
                            None
                        } else {Some((uuid, (ep, callback, ids)))}
                })));

                self.completed = Some(BTreeMap::from_iter(self.completed.take().unwrap().into_iter().flat_map(|(uuid, res)| {
                    if self.waiting.as_ref().unwrap().iter().any(|(_, (_, _, ids))| ids.contains(&uuid)) ||
                        self.original_requests.as_ref().unwrap().contains(&uuid) {
                        Some((uuid, res))
                    } else {None}
                })));

                //if self.no_ready_tasks() && self.no_request_tasks() && !self.no_waiting_tasks()  {self.print(); panic!("Compiler stuck");}

                if self.no_ready_tasks() {
                    if !self.no_request_tasks() {
                        let mut requests: BTreeMap<(Endpoint, Uuid), (Uuid, AgentRequest)> = BTreeMap::new();

                        for (uuid, (ep, req)) in self.requests.replace(Default::default()).unwrap() {
                            let id = req.get_id();
                            let key = (ep.clone(), id);
                            match requests.get(&key) {
                                Some((ouid, oreq)) => {
                                    if req == *oreq {
                                        self.wait_on(uuid, ep, *ouid);
                                    } else {
                                        match (req.priority(), oreq.priority()) {
                                            (None, None) => {
                                                panic!("two different immutable request to same ep and key");
                                            },
                                            (Some(p), Some(o)) if p == o => {panic!("Two mutable requests with same prio for same ep and key");},
                                            (Some(p), Some(o)) if p > o => {
                                                self.wait_on(*ouid, ep, uuid);
                                                requests.remove(&key);
                                                requests.insert(key, (uuid, req));
                                            },
                                            (Some(p), Some(o)) if p < o => {self.wait_on(uuid, ep, *ouid);}
                                            _ => {panic!("Immutable and mutable request");},
                                        }
                                    }
                                },
                                None => {
                                    requests.insert(key, (uuid, req));
                                }
                            }
                        }
                        let mut ep_requests: BTreeMap<Endpoint, BTreeMap<Uuid, Box<DwnRequest>>> = BTreeMap::new();

                        let keys: BTreeMap<Uuid, (Endpoint, Uuid)> = requests.into_iter().map(|((ep, id), (uuid, req))| {
                            let req = Box::new(req.into_dwn_request().unwrap());
                            match ep_requests.get_mut(&ep) {
                                Some(ep_map) => {ep_map.insert(id, req);},
                                None => {ep_requests.insert(ep.clone(), BTreeMap::from([(id, req)]));}
                            }
                            (uuid, (ep, id))
                        }).collect();

                        let responses: Vec<(Uuid, BoxResponse)> = match self.router.send(ep_requests).await {
                            Err(e) => {
                                let error = Box::new(ErrorWrapper::new(e)) as BoxResponse;
                                keys.into_keys().map(|k| (k, error.clone())).collect()
                            },
                            Ok(resps) => keys.into_iter().map(|(uuid, (ep, id))|
                                (uuid, Box::new(resps.get(&ep).unwrap().get(&id).cloned().unwrap_or_default()) as BoxResponse)
                            ).collect()
                        };

                        self.completed.as_mut().unwrap().extend(responses);
                    }
                    if self.no_ready_tasks() && self.no_waiting_tasks() && self.no_request_tasks() {
                        break;
                    }
                }
            }
        }
        let mut responses = self.completed.replace(Default::default()).unwrap();
        (self.original_requests.replace(Default::default()).unwrap().into_iter().map(|uuid| {
            *responses.remove(&uuid).unwrap().downcast::<Vec<Box<dyn Response>>>().unwrap()
        }).collect(), self.memory)
    }
}
