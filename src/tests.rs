use crate::error::Error;

use simple_database::MemoryStore;
use simple_database::database::{Filter, FiltersBuilder};

use simple_crypto::Hashable;

use crate::dids::{DidResolver, DidDocument};
use crate::dids::{
    Identity,
    Did,
};
use crate::dids::DhtDocument;

use crate::Record;
use crate::{ChannelPermissionOptions, PermissionOptions};
use crate::{ChannelProtocol, Protocol};
use crate::{Server, Agent, Wallet};
use crate::json_rpc::JsonRpcClient;

use crate::common::Schemas;

use std::path::PathBuf;
use std::collections::BTreeMap;


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

        let opt_did_resolver: Option<Box<dyn DidResolver>> = Some(Box::new(did_resolver.clone()));

        //RemoteDwns
        let ard = Server::new::<MemoryStore>(
            ard_did.clone(), ard_id.com_key, Some(PathBuf::from("server1")), opt_did_resolver.clone(), None
        ).await?;
        let ard =  tokio::spawn(ard.start_server(ard_port).await?);

        let brd = Server::new::<MemoryStore>(
            brd_did.clone(), brd_id.com_key, Some(PathBuf::from("server2")), opt_did_resolver.clone(), None
        ).await?;
        let brd = tokio::spawn(brd.start_server(brd_port).await?);

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
                Some(vec![&messages_protocol])
            ))
        )?;
        println!("room_protocol: {}", rooms_protocol.hash());

        let protocols = vec![rooms_protocol.clone(), messages_protocol.clone()];

        //Wallet
        let a_wallet = Wallet::new(a_id, Box::new(did_resolver.clone()), None);
        let b_wallet = Wallet::new(b_id, Box::new(did_resolver.clone()), None);

        //Agent
        let alice_agent = Agent::new::<MemoryStore>(
            a_wallet.get_agent_key(&rooms_protocol).await?,
            protocols.clone(),
            None,
            opt_did_resolver.clone(),
            None,
        ).await?;

        let bob_agent = Agent::new::<MemoryStore>(
            b_wallet.get_agent_key(&rooms_protocol).await?,
            protocols.clone(),
            None,
            opt_did_resolver.clone(),
            None,
        ).await?;


        let record = Record::new(None, &rooms_protocol, serde_json::to_vec("HELLOWORLD")?);
        let record_id = record.record_id;
        alice_agent.public_create(record, BTreeMap::default(), None).await?;

        let filters = FiltersBuilder::build(vec![
            ("primary_key", Filter::equal(record_id.as_bytes().to_vec()))
        ]);
        println!("{:#?}", alice_agent.public_read(filters.clone(), None, None).await?.len());

        let record = Record::new(Some(record_id), &rooms_protocol, serde_json::to_vec("H")?);
        alice_agent.public_update(record, BTreeMap::default(), None).await?;
        println!("{:#?}", alice_agent.public_read(filters.clone(), None, None).await?.len());

        alice_agent.public_delete(record_id, None).await?;
        println!("{:#?}", alice_agent.public_read(filters, None, None).await?.len());

        let record = Record::new(None, &rooms_protocol, serde_json::to_vec("HELLOWORLD")?);
        let root_path = vec![rooms_protocol.uuid()];
        let room_path = vec![rooms_protocol.uuid(), record.record_id];
        println!("ALICE CREATE");
        alice_agent.create(
            &root_path,
            Some(&PermissionOptions::new(true, true, false, Some(
                ChannelPermissionOptions::new(true, true, true)
            ))),
            record,
            Some(&[&a_did, &b_did])
        ).await?;

        println!("ALICE READ");

        println!("record: {:#?}", alice_agent.read(&root_path, None, None).await?.is_some());
        println!("record: {:#?}", alice_agent.read(&root_path, Some((0, None)), None).await?.is_some());
        println!("record: {:#?}", alice_agent.read(&room_path, None, None).await?.is_some());

        println!("ALICE SHARE");

        alice_agent.share(&room_path, &PermissionOptions::new(true, true, false, Some(
            ChannelPermissionOptions::new(true, true, true)
        )), &b_did).await?;

        println!("BOB SCAN");

        bob_agent.scan().await?;

        println!("BOB READ");

        println!("record: {:#?}", bob_agent.read(&root_path, Some((0, None)), None).await?.is_some());

        println!("record: {:#?}", bob_agent.read(&room_path, None, None).await?.is_some());


        println!("ARD: {}", JsonRpcClient::client_debug("http://localhost:3000").await);
        println!("BRD: {}", JsonRpcClient::client_debug("http://localhost:3001").await);
        assert!(false);
        Ok(())
    }.await;
    if result.is_err() {
        println!("{:#?}", result);
    }
    assert!(result.is_ok());
}
