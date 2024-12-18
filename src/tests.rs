//  use crate::error::Error;

//  #[tokio::test]
//  async fn group_messaging() -> Result<(), Error> {
//      let err: Error = hex::decode("abcfrgb").err().unwrap().into();
//      let err: Error = Error::custom("Hello");
//      println!("err: {:#?}", err);
//      assert!(false);
//      Ok(())
//  }
use snafu::ErrorCompat;

use crate::error::Error;

use simple_database::MemoryStore;
use simple_database::database::{Filter, Filters};

use simple_crypto::Hashable;

use crate::dids::{DidResolver, DidDocument};
use crate::dids::Did;
use crate::dids::DhtDocument;

use crate::dwn::json_rpc::{JsonRpcClient, JsonRpcServer};
use crate::dwn::traits::Server;
use crate::dwn::structs::PublicRecord;
use crate::dwn::{Dwn, DwnIdentity};

use crate::agent::{Wallet, Agent, Identity};
use crate::agent::structs::{RecordPath, Record};
use crate::agent::permission::{ChannelPermissionOptions, PermissionOptions};
use crate::agent::protocol::{ChannelProtocol, Protocol};

use crate::common::Schemas;


use std::path::PathBuf;
use std::collections::BTreeMap;

use uuid::Uuid;

use crate::agent::scripts::*;


pub type Docs = BTreeMap<Did, Box<dyn DidDocument>>;

#[derive(Clone)]
pub struct MemoryDidResolver {
    pub docs: Docs
}

impl MemoryDidResolver {
    fn new() -> Self {MemoryDidResolver{docs: Docs::default()}}
    pub fn store(&mut self, doc: Box<dyn DidDocument>) {
        self.docs.insert(doc.did(), doc);
    }
}

#[async_trait::async_trait]
impl DidResolver for MemoryDidResolver {
    async fn resolve(&self, did: &Did) -> Result<Option<Box<dyn DidDocument>>, Error> {
        Ok(self.docs.get(did).cloned())
    }
}

impl std::fmt::Debug for MemoryDidResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryDidResolver")
        .field("dids", &self.docs.keys().map(|did| did.to_string()).collect::<Vec<String>>())
        .finish()
    }
}

fn get_user(servers: Vec<Did>) -> Result<(Identity, DhtDocument), Error> {
    Identity::new(servers.iter().map(|d| d.to_string()).collect())
}

fn get_server(ports: Vec<u32>) -> Result<(DwnIdentity, DhtDocument), Error> {
    DwnIdentity::new(ports.iter().map(|p| format!("http://localhost:{}", p)).collect())
}

async fn run_test() -> Result<(), Error> {
    let mut did_resolver = MemoryDidResolver::new();

    let ard_port = 3000;
    let (ard_id, ard_doc) = get_server(vec![ard_port])?;
    let ard_did = ard_doc.did();
    did_resolver.store(Box::new(ard_doc.clone()));

    let brd_port = 3001;
    let (brd_id, brd_doc) = get_server(vec![brd_port])?;
    let brd_did = brd_doc.did();
    did_resolver.store(Box::new(brd_doc.clone()));

    let crd_port = 3002;
    let (crd_id, crd_doc) = get_server(vec![crd_port])?;
    let crd_did = crd_doc.did();
    did_resolver.store(Box::new(crd_doc.clone()));


    let (a_id, a_doc) = get_user(vec![ard_did.clone()])?;
    let a_did = a_doc.did();
    did_resolver.store(Box::new(a_doc.clone()));

    let (b_id, b_doc) = get_user(vec![brd_did.clone()])?;
    let b_did = b_doc.did();
    did_resolver.store(Box::new(b_doc.clone()));

    let (c_id, c_doc) = get_user(vec![crd_did.clone()])?;
    let c_did = c_doc.did();
    did_resolver.store(Box::new(c_doc.clone()));

    let did_resolver: Box<dyn DidResolver> = Box::new(did_resolver.clone());


    //RemoteDwns
    let ard = Dwn::new::<MemoryStore>(
        ard_id, Some(PathBuf::from("servera")), Some(did_resolver.clone())
    ).await?;
    let ard = tokio::spawn(JsonRpcServer{}.start_server(ard, ard_port).await?);

    let brd = Dwn::new::<MemoryStore>(
        brd_id, Some(PathBuf::from("serverb")), Some(did_resolver.clone())
    ).await?;
    let brd = tokio::spawn(JsonRpcServer{}.start_server(brd, brd_port).await?);

    let crd = Dwn::new::<MemoryStore>(
        crd_id, Some(PathBuf::from("serverc")), Some(did_resolver.clone())
    ).await?;
    let crd = tokio::spawn(JsonRpcServer{}.start_server(crd, crd_port).await?);


    let messages_protocol = Protocol::new(
        "Message",
        true,
        PermissionOptions::new(true, true, false, None),
        Some(serde_json::to_string(&Schemas::any()).unwrap()),
        None
    )?;
    println!("messages_protocol: {}", messages_protocol.hash());

    let rooms_protocol = Protocol::new(
        "Room",
        false,
        PermissionOptions::new(true, true, false, Some(
            ChannelPermissionOptions::new(true, true)
        )),
        Some(serde_json::to_string(&Schemas::any()).unwrap()),
        Some(ChannelProtocol::new(
            Some(vec![&messages_protocol])
        ))
    )?;
    println!("room_protocol: {}", rooms_protocol.hash());

    let protocols = vec![rooms_protocol.clone(), messages_protocol.clone()];

    //Wallet
  //let a_wallet = Wallet::new(a_id, Box::new(did_resolver.clone()), None);
    //let b_wallet = Wallet::new(b_id);//, Box::new(did_resolver.clone()), None);
    let a_wallet = Wallet::new(a_id);

    //Agent
    let alice_agent = Agent::new(
        a_wallet.root(),
        protocols.clone(),
        did_resolver,
        Box::new(JsonRpcClient{})
    );

    let mut mem = alice_agent.new_compiler_memory();

    let mut compiler = alice_agent.new_compiler(mem);

    let record = PublicRecord::new(None, rooms_protocol.uuid(), b"\"HELLOE\"", None)?;
    let id = record.uuid;
    compiler.add_command(
        CreatePublic::new(record, None),
        Some(vec![a_did.clone()])
    ).await?;

//  let record = Record::new(RecordPath::new(&[Uuid::new_v4()]), rooms_protocol.uuid(), b"\"HELLOE\"");
//  compiler.add_command(
//      CreatePrivate::new(record, None),
//      Some(vec![a_did.clone()])
//  ).await?;


    let (res, mem) = compiler.compile().await;
    println!("R: {:#?}", res);
  //let mut compiler = alice_agent.new_compiler(mem);

  //let record = PublicRecord::new(Some(id), rooms_protocol.uuid(), b"\"H\"", None)?;
  //compiler.add_command(
  //    UpdatePublic::new(record, None),
  //    Some(vec![a_did.clone()])
  //).await?;

  //let (res, mem) = compiler.compile().await;
  //println!("R: {:#?}", res);
  //let mut compiler = alice_agent.new_compiler(mem);

  //let filters = Filters::new(vec![
  //    ("signer", Filter::equal(a_did.to_string()))
  //]);

  //compiler.add_command(
  //    ReadPublic::new(filters, None),
  //    Some(vec![a_did.clone()])
  //).await?;

  //let (res, mem) = compiler.compile().await;
  //println!("R: {:#?}", res);
  //let mut compiler = alice_agent.new_compiler(mem);

  //compiler.add_command(
  //    DeletePublic::new(id, None),
  //    Some(vec![a_did.clone()])
  //).await?;

  //let (res, mem) = compiler.compile().await;
  //println!("R: {:#?}", res);


    println!("ARD: {}", JsonRpcClient::client_debug("http://localhost:3000").await);
    println!("BRD: {}", JsonRpcClient::client_debug("http://localhost:3001").await);
    assert!(false);
    Ok(())
}


#[tokio::test]
async fn group_messaging() {
    let result: Result<(), Error> = run_test().await;
    if let Err(err) = result {
        println!("{:#?}", err);
        assert!(false);
    }
}
