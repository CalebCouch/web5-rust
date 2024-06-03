use crate::error::Error;

use crate::common::structs::Url;
use crate::common::MemoryStore;
use crate::common::traits::KeyValueStore;

use crate::crypto::secp256k1::{SecretKey, PublicKey};
use crate::crypto::ed25519;
use crate::crypto::traits::{BHash, Hashable};
use crate::crypto::structs::Hash;

use crate::dids::traits::{DidResolver, DidDocument};
use crate::dids::structs::{
    DidKeyPurpose,
    DidKeyPair,
    DidService,
    DidMethod,
    DidKey,
    Did,
};
use crate::dids::DhtDocument;

use crate::dwn::structs::{Packet, Action, Record};
use crate::dwn::protocol::Protocol;
use crate::dwn::json_rpc::JsonRpc;
use crate::dwn::{DwnServer, Agent};
use crate::{Server};

use std::path::PathBuf;
use std::collections::BTreeMap;
use std::str::FromStr;

use schemars::{schema_for, JsonSchema};
use serde::{Serialize, Deserialize};

pub type Docs = BTreeMap<Did, Box<dyn DidDocument>>;

#[derive(Clone)]
pub struct MemoryDidResolver {
    pub docs: Docs
}

impl MemoryDidResolver {
    pub fn store(&mut self, doc: Box<dyn DidDocument>) {
        self.docs.insert(doc.did(), doc);
    }
}

#[async_trait::async_trait]
impl DidResolver for MemoryDidResolver {
    fn new() -> Self where Self: Sized {MemoryDidResolver{docs: Docs::default()}}
    async fn resolve(&self, did: &Did) -> Result<Option<Box<dyn DidDocument>>, Error> {
        Ok(self.docs.get(did).cloned())
    }
}

impl std::fmt::Debug for MemoryDidResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryDidResolver")
        .field("dids", &self.docs.iter().map(|(did, doc)| did.to_string()).collect::<Vec<String>>())
        .finish()
    }
}

fn new_did_doc(
    did_resolver: &mut MemoryDidResolver,
    service_endpoints: Vec<String>
) -> Result<(DhtDocument, SecretKey), Error> {

    let id_key = ed25519::SecretKey::new().public_key();

    let sec_key = SecretKey::new();
    let key = DidKey::new(
        Some("key".to_string()),
        Did::new(DidMethod::DHT, id_key.thumbprint()),
        sec_key.public_key(),
        vec![DidKeyPurpose::Auth, DidKeyPurpose::Asm, DidKeyPurpose::Agm],
        None
    );

    let mut keys = BTreeMap::default();
    keys.insert("key".to_string(), key);

    let mut services = BTreeMap::default();
    services.insert("dwn".to_string(), DidService::new_dwn(service_endpoints));

    let doc = DhtDocument::new(id_key, Vec::new(), Vec::new(), services, keys, Vec::new());
    did_resolver.store(Box::new(doc.clone()));
    Ok((doc, sec_key))
}

fn get_user(did_resolver: &mut MemoryDidResolver, servers: Vec<Did>) -> Result<(DhtDocument, SecretKey), Error> {
    let (doc, key) = new_did_doc(did_resolver, servers.iter().map(|d| d.to_string()).collect())?;
    Ok((doc, key))
}

fn get_server(did_resolver: &mut MemoryDidResolver, ports: Vec<u32>) -> Result<(DhtDocument, SecretKey), Error> {
    new_did_doc(did_resolver, ports.iter().map(|p| format!("http://localhost:{}", p)).collect())
}

#[derive(JsonSchema, Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RoomPayload {
    pub name: String
}

#[derive(JsonSchema, Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MessagePayload {
    pub text: String
}

#[tokio::test]
async fn group_messaging() {
    let result: Result<(), Error> = async {
        let mut did_resolver = MemoryDidResolver::new();

        //RemoteDwnInfo
        let ard_port = 3000;
        let (ard_doc, ard_key) = get_server(&mut did_resolver, vec![ard_port])?;
        let ard_did = ard_doc.did();
        let brd_port = 3001;
        let (brd_doc, brd_key) = get_server(&mut did_resolver, vec![brd_port])?;
        let brd_did = brd_doc.did();


        //Ids
        let (a_doc, a_key) = get_user(&mut did_resolver, vec![ard_did.clone()])?;
        let a_did = a_doc.did();
        let (b_doc, b_key) = get_user(&mut did_resolver, vec![brd_did.clone()])?;
        let b_did = b_doc.did();

        //Dids
        println!("ALICE: {}", a_key);
        println!("DID: {}", a_did);
        println!("BOB: {}", b_key);
        println!("DID: {}", b_did);

        //RemoteDwns
        let mut ard = Server::new::<MemoryStore>(
            Some(PathBuf::from("server1")), ard_did.clone(), ard_key.clone(), Some(Box::new(did_resolver.clone()))
        )?;
        tokio::spawn(ard.get_server(ard_port)?);
        let mut brd = Server::new::<MemoryStore>(
            Some(PathBuf::from("server2")), brd_did.clone(), brd_key.clone(), Some(Box::new(did_resolver.clone()))
        )?;
        tokio::spawn(brd.get_server(brd_port)?);

        //Agents
        let mut alice_agent = Agent::new::<MemoryStore>(
            DidKeyPair::new(key.clone(), doc.get_key("key").unwrap().clone()).unwrap(),
            Some(PathBuf::from("AGENT")), None, None
        ).await?;

      //let mut alice_agent2 = Agent::new::<MemoryStore>(
      //    DidKeyPair::new(a_key.clone(), a_doc.get_key("key").unwrap().clone()).unwrap(),
      //    Some(PathBuf::from("ALICE_AGENT2")),
      //    Some(Box::new(did_resolver.clone())),
      //    None
      //).await?;

//      let (create, record) = alice_agent.create(&Protocol::folder().hash(), &serde_json::to_vec(&b"HELLO".to_vec().hash())?).await?;
//      alice_agent.client.create(&a_did, &create, record).await?;
//      let (create, record) = alice_agent.create(&Protocol::file().hash(), &serde_json::to_vec(&"HELLO")?).await?;
//      alice_agent.client.create(&a_did, &create, record).await?;


//      //alice_agent.set(b"IHAE", b"VMAYLUE").await?;
//      //alice_agent.set(b"IHAE", b"VMAYLUE2").await?;
//      //alice_agent.send_dm(&b_did, b"MYMESSAGETOBOB".to_vec()).await?;
//      //alice_agent.delete(b"IHAE").await?;

        let mut bob_agent = Agent::new::<MemoryStore>(
            DidKeyPair::new(b_key.clone(), b_doc.get_key("key").unwrap().clone()).unwrap(),
            Some(PathBuf::from("BOB_AGENT")),
            Some(Box::new(did_resolver.clone())),
            None
        ).await?;

        let record = Record::new(None, Protocol::folder().hash(), serde_json::to_vec("HELLOWORLD")?);
        let folder_id = record.record_id.clone();
        let perm = alice_agent.create(None, record, &[&a_did]).await?;
      //println!("{:?}", alice_agent.read(&folder_id, &[&a_did]).await?);
      //let record = Record::new(None, Protocol::file().hash(), serde_json::to_vec(b"HELLOWORLD")?);
      //alice_agent.create(Some(&folder_id), record, &[&a_did]).await?;
      //alice_agent.delete_child(&folder_id, 0, &[&a_did]).await?;
      //println!("{:?}", alice_agent.read_child(&folder_id, 0, &[&a_did]).await?);

        alice_agent.send_dm(&b_did, perm.clone()).await?;
        println!("READ DMS");
        println!("{:?}", bob_agent.read_dms(&a_did, 0, None).await?);
      //alice_agent.establish_dms(&b_did).await?;
      //bob_agent.establish_dms(&a_did).await?;

//      println!("ARD: {}", JsonRpc::new(None, Box::new(did_resolver.clone())).debug("http://localhost:3000").await?);
//      println!("{}", "DMS");

//    //bob_agent.send_dm(&a_did, b"MYMESSAGETOALICE".to_vec()).await?;
        //alice_agent.establish_dms(&b_did).await?;
        //bob_agent.process_dms().await?;

//      let message_protocol = Protocol{
//          schema: Some(serde_json::to_string(&schema_for!(MessagePayload)).unwrap()),
//          actions: vec![Action::Read],
//          child_actions: vec![],
//          children: vec![],
//          allow_extra_keys: false,
//      };

//      let room_protocol = Protocol{
//          schema: Some(serde_json::to_string(&schema_for!(RoomPayload)).unwrap()),
//          actions: vec![Action::CreateChild, Action::Read],
//          child_actions: vec![Action::CreateChild, Action::Read],
//          children: vec![message_protocol.hash()],
//          allow_extra_keys: false,
//      };

//      alice_agent.configure_protocol(&message_protocol).await?;
//      alice_agent.configure_protocol(&room_protocol).await?;
//      let mut alice_agent2 = Agent::new::<MemoryStore>(
//          Some(PathBuf::from("ALICE_AGENT2")),
//          DidKeyPair::new(a_key.clone(), a_doc.get_key("key").unwrap().clone()).unwrap(),
//          Some(Box::new(did_resolver.clone())),
//          None
//      ).await?;


//      //println!("ALICE: {:#?}", alice_agent.processor);
//      let room = alice_agent.create(
//          None,
//          &room_protocol.hash(),
//          &serde_json::to_vec(&RoomPayload{name: "MyROOM".to_string()})?
//      ).await?;

//      let msg1 = alice_agent.create(
//          Some(room.inner().record_id()),
//          &message_protocol.hash(),
//          &serde_json::to_vec(&MessagePayload{text: "My message in my room".to_string()})?
//      ).await?;

        //bob_agent.configure_protocol(&room_protocol).await?;
      //let alice_perms = Permission::new(
      //    bob_did.clone(),
      //    alice_did.clone(),
      //    vec![Action::Create],
      //    Some(room_protocol.get_cid()),
      //    None,
      //    vec![]
      //);
      //let perm = bob_agent.permission(&alice_perms).await?;
      //println!("PERM CID: {}", perm.message.id());
      ////alice_agent.send(&bob_did, &room, false, false).await?;


        println!("ARD: {}", JsonRpc::new().debug("http://localhost:3000").await?);
        println!("BRD: {}", JsonRpc::new().debug("http://localhost:3001").await?);
        println!("ALICE: {:#?}", alice_agent);
        //println!("ALICE2: {:#?}", alice_agent2.processor);
        //println!("BOB: {:#?}", bob_agent);
        assert!(false);
        Ok(())
    }.await;
    if result.is_err() {
        println!("{:#?}", result);
    }
    assert!(result.is_ok());
}
