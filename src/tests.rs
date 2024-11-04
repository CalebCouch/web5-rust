use crate::error::Error;

use simple_database::{KeyValueStore, MemoryStore};
use simple_database::database::{Filters, Filter, FiltersBuilder, SortOptions};

use simple_crypto::{SecretKey, PublicKey, Hashable, Hash};
use crate::ed25519;

use crate::dids::traits::{DidResolver, DidDocument};
use crate::dids::structs::{
    Identity,
    DidKeyPurpose,
    DidKeyPair,
    DidService,
    DidMethod,
    DidKey,
    Did,
};
use crate::dids::DhtDocument;

use crate::dwn::structs::{Packet, Action, Record, DwnKey};
use crate::dwn::permission::{ChannelPermissionOptions, PermissionOptions};
use crate::dwn::protocol::{ChannelProtocol, Protocol};
use crate::dwn::json_rpc::JsonRpc;
use crate::dwn::{Server, Agent, Wallet};

use crate::common::Schemas;

use std::path::PathBuf;
use std::collections::BTreeMap;
use std::str::FromStr;

use schemars::{schema_for, JsonSchema};
use serde::{Serialize, Deserialize};
use either::Either;
use url::Url;

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

fn get_user(servers: Vec<Did>) -> Result<(DhtDocument, Identity), Error> {
    DhtDocument::default(servers.iter().map(|d| d.to_string()).collect())
}

fn get_server(ports: Vec<u32>) -> Result<(DhtDocument, Identity), Error> {
    DhtDocument::default(ports.iter().map(|p| format!("http://localhost:{}", p)).collect())
}

#[tokio::test]
async fn group_messaging() {
    let result: Result<(), Error> = async {
        let mut did_resolver = MemoryDidResolver::new();

        //RemoteDwnInfo
        let ard_port = 3000;
        let (ard_doc, ard_id) = get_server(vec![ard_port])?;
        let ard_did= ard_id.sig_key.public.did.clone();
        did_resolver.store(Box::new(ard_doc.clone()));
        let brd_port = 3001;
        let (brd_doc, brd_id) = get_server(vec![brd_port])?;
        let brd_did = brd_id.sig_key.public.did.clone();
        did_resolver.store(Box::new(brd_doc.clone()));

        //Ids
        let (a_doc, a_id) = get_user(vec![ard_did.clone()])?;
        let a_did = a_id.sig_key.public.did.clone();
        did_resolver.store(Box::new(a_doc.clone()));
        let (b_doc, b_id) = get_user(vec![brd_did.clone()])?;
        let b_did = b_id.sig_key.public.did.clone();
        did_resolver.store(Box::new(b_doc.clone()));

        //Dids

        //RemoteDwns
        let mut ard = Server::new::<MemoryStore>(
            ard_did.clone(), ard_id.com_key, Some(PathBuf::from("server1")), None, Some(Box::new(did_resolver.clone()))
        )?;
        ard.start_server(ard_port).await?;

        let mut brd = Server::new::<MemoryStore>(
            brd_did.clone(), brd_id.com_key, Some(PathBuf::from("server2")), None, Some(Box::new(did_resolver.clone()))
        )?;
        brd.start_server(brd_port).await?;

        //Protocols
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
                ChannelPermissionOptions::new(true, true, true)
            )),
            Some(serde_json::to_string(&Schemas::any()).unwrap()),
            Some(ChannelProtocol::new(
                Some(vec![messages_protocol.hash()])
            ))
        )?;
        println!("room_protocol: {}", rooms_protocol.hash());

        let mut protocols = BTreeMap::default();
        let pf = Protocol::protocol_folder(&rooms_protocol.hash());
        protocols.insert(pf.hash(), pf);
        protocols.insert(rooms_protocol.hash(), rooms_protocol.clone());
        protocols.insert(messages_protocol.hash(), messages_protocol.clone());

        //Wallet
        let did_resolver: Option<Box<dyn DidResolver>> = Some(Box::new(did_resolver.clone()));
        let a_wallet = Wallet::new(
            a_id,
            Some(Box::new(JsonRpc::new(did_resolver.clone()))),
            did_resolver.clone(),
        );

        let b_wallet = Wallet::new(
            b_id,
            Some(Box::new(JsonRpc::new(did_resolver.clone()))),
            did_resolver.clone(),
        );

        //Agent
        let mut alice_agent = Agent::new(
            a_wallet.get_agent_key(&rooms_protocol.hash()).await?,
            protocols.clone(),
            Some(Box::new(JsonRpc::new(did_resolver.clone()))),
            did_resolver.clone(),
        );

        let mut bob_agent = Agent::new(
            b_wallet.get_agent_key(&rooms_protocol.hash()).await?,
            protocols.clone(),
            Some(Box::new(JsonRpc::new(did_resolver.clone()))),
            did_resolver.clone(),
        );


        let record = Record::new(None, rooms_protocol.hash(), serde_json::to_vec("HELLOWORLD")?);
        let record_id = record.record_id;
        alice_agent.public_create(record, BTreeMap::default(), &[&a_did]).await?;

        let filters = FiltersBuilder::build(vec![
            ("primary_key", Filter::equal(record_id.to_vec()))
        ]);
        println!("{:#?}", alice_agent.public_read(filters.clone(), None, &[&a_did]).await?);

        let record = Record::new(Some(record_id), rooms_protocol.hash(), serde_json::to_vec("H")?);
        alice_agent.public_update(record, BTreeMap::default(), &[&a_did]).await?;
        println!("{:#?}", alice_agent.public_read(filters.clone(), None, &[&a_did]).await?);

        alice_agent.public_delete(record_id, &[&a_did]).await?;
        println!("{:#?}", alice_agent.public_read(filters, None, &[&a_did]).await?);




        let record = Record::new(None, rooms_protocol.hash(), serde_json::to_vec("HELLOWORLD")?);
        let root_path = vec![rooms_protocol.hash()];
        let room_path = vec![rooms_protocol.hash(), record.record_id];
        println!("ALICE CREATE");
        alice_agent.create(
            &root_path,
            Some(&PermissionOptions::new(true, true, false, Some(
                ChannelPermissionOptions::new(true, true, true)
            ))),
            record,
            &[&a_did, &b_did]
        ).await;

        println!("ALICE READ");

        println!("record: {:#?}", alice_agent.read(&root_path, None, &[&a_did]).await?.is_some());
        println!("record: {:#?}", alice_agent.read(&root_path, Some((0, None)), &[&a_did]).await?.is_some());
        println!("record: {:#?}", alice_agent.read(&room_path, None, &[&a_did]).await?.is_some());

        println!("ALICE SHARE");

        alice_agent.share(&room_path, &PermissionOptions::new(true, true, false, Some(
            ChannelPermissionOptions::new(true, true, true)
        )), &b_did).await?;

        println!("BOB SCAN");

        bob_agent.scan().await?;

        println!("BOB READ");

        println!("record: {:#?}", bob_agent.read(&root_path, Some((0, None)), &[&b_did]).await?.is_some());

        println!("record: {:#?}", bob_agent.read(&room_path, None, &[&b_did]).await?.is_some());


        println!("ARD: {}", JsonRpc::new(did_resolver.clone()).client_debug("http://localhost:3000").await?);
        println!("BRD: {}", JsonRpc::new(did_resolver.clone()).client_debug("http://localhost:3001").await?);
        assert!(false);
        Ok(())
    }.await;
    if result.is_err() {
        println!("{:#?}", result);
    }
    assert!(result.is_ok());
}
