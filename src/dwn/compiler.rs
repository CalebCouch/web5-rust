use super::Error;

use crate::dwn::request_builder::PrivateRecord;
use crate::dwn::request_builder::DwnRequest;
use crate::dwn::structs::DwnKey;
use crate::dwn::router::Router;
use crate::dwn::router::DwnResponse;
use crate::dwn::Protocol;

use crate::dids::Did;

use std::collections::BTreeMap;
use std::sync::Arc;

use uuid::Uuid;

pub mod system;
pub mod public;

pub type Protocols<'a> = &'a BTreeMap<Uuid, Protocol>;
pub type RecordPath = Vec<Uuid>;
pub type BoxCallback<'a> = Box<dyn FnOnce(Results) -> BoxCommand<'a> + 'a>;
pub type Results = Vec<Response>;
pub type Dids<'a> = &'a [&'a Did];
pub type BoxCommand<'a> = Box<dyn Command<'a> + 'a>;

#[derive(Clone)]
pub enum Response {
    PrivateRecord(Option<Box<PrivateRecord>>),
    Index(usize),
    Exists(bool),
    DwnResponse(Vec<DwnResponse>),
    InvalidAuth(String),
    Error(Arc<Error>),
    Conflict,
    Empty,
}

impl std::fmt::Debug for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PrivateRecord(_) => write!(f, "PrivateRecord"),
            Self::Index(_) => write!(f, "Index"),
            Self::Exists(_) => write!(f, "Exists"),
            Self::DwnResponse(_) => write!(f, "DwnResponse"),
            Self::InvalidAuth(_) => write!(f, "InvalidAuth"),
            Self::Error(e) => write!(f, "Error: {:?}", e),
            Self::Conflict => write!(f, "Conflict"),
            Self::Empty => write!(f, "Empty"),
        }
    }
}

impl Response {
    pub fn is_invalid_auth(&self) -> bool {
        matches!(self, Self::InvalidAuth(_))
    }

    pub fn handle_error(self) -> Result<Self, Arc<Error>> {
        match self {
            Self::Error(error) => Err(error.into()),
            other => Ok(other)
        }
    }

    pub fn as_dwn_responses(self) -> Result<Vec<DwnResponse>, Error> {
        match self {
            Self::DwnResponse(resps) => Ok(resps),
            other => Err(Error::BadResponse(format!("Expected DwnResponse(_) Got {:?}", other)))
        }
    }

    pub fn as_index(self) -> Result<usize, Error> {
        match self {
            Self::Index(i) => Ok(i),
            other => Err(Error::BadResponse(format!("Expected Index(_) Got {:?}", other)))
        }
    }

    pub fn as_private_record(self) -> Result<Option<PrivateRecord>, Error> {
        match self {
            Self::PrivateRecord(pr) => Ok(pr.map(|pr| *pr)),
            other => Err(Error::BadResponse(format!("Expected PrivateRecord(_) Got {:?}", other)))
        }
    }

    pub fn as_exists(self) -> Result<bool, Error> {
        match self {
            Self::Exists(i) => Ok(i),
            other => Err(Error::BadResponse(format!("Expected Exists(_) Got {:?}", other)))
        }
    }
}

pub trait Command<'a>: std::fmt::Debug {
    fn process(
        self: Box<Self>, uuid: Uuid, protocols: Protocols<'a>, enc_key: &'a DwnKey
    ) -> Result<Vec<(Uuid, Task<'a>)>, Error>;
}


pub enum Task<'a> {
    Ready(BoxCommand<'a>),
    Request(DwnRequest, Dids<'a>),
    Waiting(Vec<Uuid>, BoxCallback<'a>),
    Completed(Response),
}

pub struct Compiler<'a> {
    original_requests: Option<Vec<Uuid>>,
    ready: Option<BTreeMap<Uuid, BoxCommand<'a>>>,
    requests: Option<BTreeMap<Uuid, (DwnRequest, Dids<'a>)>>,
    waiting: Option<BTreeMap<Uuid, (Vec<Uuid>, BoxCallback<'a>)>>,
    completed: Option<BTreeMap<Uuid, Response>>,

    protocols: Protocols<'a>, router: &'a Router<'a>, key: &'a DwnKey
}

impl<'a> Compiler<'a> {
    pub fn new(
        protocols: Protocols<'a>, router: &'a Router<'a>, key: &'a DwnKey
    ) -> Self {
        Compiler{
            original_requests: Some(Vec::new()),
            ready: Some(BTreeMap::default()),
            requests: Some(BTreeMap::default()),
            waiting: Some(BTreeMap::default()),
            completed: Some(BTreeMap::default()),
            protocols,
            router,
            key
        }
    }

    pub fn add_command(&mut self, command: BoxCommand<'a>) {
        let id = Uuid::new_v4();
        self.original_requests.as_mut().unwrap().push(id);
        self.ready.as_mut().unwrap().insert(id, command);
    }

    pub fn no_ready_tasks(&self) -> bool {
        self.ready.as_ref().unwrap().is_empty()
    }

    pub fn no_waiting_tasks(&self) -> bool {
        self.waiting.as_ref().unwrap().is_empty()
    }

    pub fn no_request_tasks(&self) -> bool {
        self.requests.as_ref().unwrap().is_empty()
    }

    fn print(&self) {
        println!("Ready: {:#?}", self.ready);
        println!("Waiting: {:#?}", self.waiting.as_ref().map(|w| w.iter().map(|(uuid, on)| (uuid, &on.0)).collect::<Vec<_>>()));
        println!("Requests: {:#?}", self.requests);
        println!("Completed: {:#?}", self.completed);
    }

    pub async fn compile(mut self) -> Result<Vec<Response>, Error> {
        loop {
            println!("COMPILE LOOP---------------");
            self.print();
            //Handle Ready Tasks
            self.ready = Some(BTreeMap::from_iter(
                self.ready.take().unwrap().into_iter().map(|(uuid, command)| {
                    match command.process(uuid, &self.protocols, &self.key) {
                        Ok(tasks) => {
                            tasks.into_iter().flat_map(|(uuid, task)| {
                                match task {
                                    Task::Ready(command) => Some((uuid, command)),
                                    Task::Request(request, dids) => {self.requests.as_mut().unwrap().insert(uuid, (request, dids)); None},
                                    Task::Waiting(ids, callback) => {self.waiting.as_mut().unwrap().insert(uuid, (ids, callback)); None},
                                    Task::Completed(completed) => {self.completed.as_mut().unwrap().insert(uuid, completed); None},
                                }
                            }).collect::<Vec<(Uuid, BoxCommand)>>()
                        }
                        Err(e) => {self.completed.as_mut().unwrap().insert(uuid, Response::Error(Arc::new(e))); vec![]}
                    }
                }).collect::<Vec<Vec<(Uuid, BoxCommand)>>>().into_iter().flatten()
            ));
            if self.no_ready_tasks() {
                println!("COMPILE W");
                self.print();

                //Handle Waiting Tasks
                self.waiting = Some(BTreeMap::from_iter(
                    self.waiting.take().unwrap().into_iter().flat_map(|(uuid, (ids, callback))| {
                        if ids.iter().all(|id| self.completed.as_ref().unwrap().contains_key(id)) {
                            let results: Vec<Response> = ids.iter().map(|id| self.completed.as_mut().unwrap().remove(id).unwrap()).collect();
                            if results.iter().any(|r| matches!(r, Response::Error(_))) {
                                let errors: Vec<Arc<Error>> = results.into_iter().flat_map(|r| if let Response::Error(err) = r {Some(err)} else {None}).collect();
                                let error = Error::Multi(format!("{:#?}", errors));
                                self.completed.as_mut().unwrap().insert(uuid, Response::Error(Arc::new(error)));
                            } else {
                                self.ready.as_mut().unwrap().insert(uuid, callback(results));
                            }
                            None
                        } else {Some((uuid, (ids, callback)))}
                    })
                ));

                if self.no_ready_tasks() {
                    println!("COMPILE R");
                    self.print();

                    //Handle Request Tasks
                    let (uuid, reqs): (Vec<Uuid>, Vec<(DwnRequest, Dids<'a>)>) = self.requests.replace(Default::default()).unwrap().into_iter().unzip();
                    let requests_len = uuid.len();
                    let results = match self.router.send(reqs).await {
                        Err(e) => vec![Response::Error(e); requests_len],
                        Ok(resps) => resps.into_iter().map(|resps| Response::DwnResponse(resps)).collect()
                    };
                    self.completed.as_mut().unwrap().extend(uuid.into_iter().zip(results));
                    if self.no_ready_tasks() && self.no_waiting_tasks() && self.no_request_tasks() {
                        break;
                    }
                }
            }
        }
        let mut results = self.completed.replace(Default::default()).unwrap();
        Ok(self.original_requests.replace(Default::default()).unwrap().into_iter().map(|uuid| {
            results.remove(&uuid).unwrap()
        }).collect())
    }
}
