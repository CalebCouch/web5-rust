use super::error::Error;

pub mod permission;
pub mod protocol;
pub mod structs;
pub mod traits;

pub mod compiler;
pub mod scripts;
pub mod commands;

use protocol::{SystemProtocols, Protocol};
use structs::PathedKey;
use compiler::{Compiler, CompilerMemory};

use crate::ed25519::SecretKey as EdSecretKey;

use crate::dwn::traits::Client;
use crate::dwn::router::Router;

use crate::dids::DidResolver;
use crate::dids::{
    DidKeyPurpose,
    DhtDocument,
    DidKeyPair,
    DidMethod,
    DidKey,
    Did
};

use std::collections::BTreeMap;

use simple_crypto::SecretKey;

use serde::{Serialize, Deserialize};
use uuid::Uuid;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Identity {
    did_key: EdSecretKey,
    sig_key: DidKeyPair,
    enc_key: PathedKey,
    com_key: PathedKey,
}

impl Identity {
    pub async fn publish_doc(&self, document: &DhtDocument) -> Result<(), Error> {
        document.publish(&self.did_key).await
    }
    pub fn new(service_endpoints: Vec<String>) -> Result<(Self, DhtDocument), Error> {
        let did_key = EdSecretKey::new();
        let did_pub = did_key.public_key();
        let sig = SecretKey::new();
        let sig_pub = sig.public_key();
        let sig_key = DidKeyPair::new(sig, DidKey::new(
            Some("sig".to_string()),
            Did::new(DidMethod::DHT, did_key.public_key().thumbprint()),
            sig_pub.clone(),
            vec![DidKeyPurpose::Auth, DidKeyPurpose::Asm, DidKeyPurpose::Agm],
            None
        )).unwrap();
        let com_key = SecretKey::new();
        let com_pub = com_key.public_key();
        Ok((
            Identity{
                did_key,
                sig_key,
                enc_key: PathedKey::new_root(SecretKey::new()),
                com_key: PathedKey::new_root(com_key),
            },
            DhtDocument::default(did_pub, sig_pub, com_pub, service_endpoints)?
        ))
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AgentKey {
    sig_key: DidKeyPair,
    enc_key: PathedKey,
    com_key: PathedKey,
    //master_protocol: Hash,
}

pub struct Wallet {
    identity: Identity
  //did_resolver: Box<dyn DidResolver>,
  //router: Box<dyn Router>,
}

impl Wallet {
    pub fn new(
        identity: Identity,
      //did_resolver: Box<dyn DidResolver>,
      //router: Option<Box<dyn Router>>,
    ) -> Self {
      //let router = router.unwrap_or(Box::new(DefaultRouter::new(did_resolver.clone(), None)));
        Wallet{
            identity
          //router,
          //did_resolver,
        }
    }

    pub fn root(&self) -> AgentKey {
        AgentKey{sig_key: self.identity.sig_key.clone(), enc_key: self.identity.enc_key.clone(), com_key: self.identity.com_key.clone()}
    }

  //pub async fn get_agent_key(&self, protocol: &Protocol) -> Result<AgentKey, Error> {
  //    let protocol_hash = protocol.hash();
  //    let pid = protocol.uuid();
  //    let root_agent_key = AgentKey::new(self.sig_key.clone(), self.enc_key.clone(), self.com_key.clone(), protocol_hash);
  //    let pf = SystemProtocols::protocol_folder(protocol_hash);
  //    let agent = Agent::new::<MemoryStore>(root_agent_key, vec![pf.clone()], None, Some(self.did_resolver.clone()), Some(self.router.clone())).await?;

  //    if agent.read(&[pid], None).await?.is_none() {
  //        agent.create(&[], &None, Record::new(Some(protocol.uuid()), &pf, Vec::new()), None).await?;
  //    }

  //    let filters = FiltersBuilder::build(vec![
  //        ("author", Filter::equal(self.tenant().to_string())),
  //        ("type", Filter::equal("agent_keys".to_string()))
  //    ]);
  //    let mut agent_keys = agent.public_read(filters, None, None).await?.first().and_then(|(_, record)|
  //        serde_json::from_slice::<Vec<PublicKey>>(&record.payload).ok()
  //    ).unwrap_or_default();

  //    let enc_key = self.enc_key.derive_path(&[pid])?;
  //    if !agent_keys.contains(&enc_key.key.public_key()) {
  //        agent_keys.push(enc_key.key.public_key());
  //        let record = Record::new(None, &SystemProtocols::agent_keys(), serde_json::to_vec(&agent_keys)?);
  //        let index = IndexBuilder::build(vec![("type", "agent_keys")]);
  //        agent.public_update(record, index, None).await?;
  //    }
  //    Ok(AgentKey::new(self.sig_key.clone(), enc_key, self.com_key.clone(), protocol_hash))
  //}
}

pub struct Agent {
    agent_key: AgentKey,
    did_resolver: Box<dyn DidResolver>,
    protocols: BTreeMap<Uuid, Protocol>,
    router: Router,
}

impl Agent {
    pub fn new(
        agent_key: AgentKey,
        protocols: Vec<Protocol>,
        did_resolver: Box<dyn DidResolver>,
        client: Box<dyn Client>
    ) -> Self {
        let protocols = [SystemProtocols::all(), protocols].concat();
        let protocols = BTreeMap::from_iter(protocols.into_iter().map(|p| (p.uuid(), p)));
        let router = Router::new(did_resolver.clone(), client);
        Agent{agent_key, did_resolver, protocols, router}
    }

    pub fn tenant(&self) -> &Did {&self.agent_key.sig_key.public.did}

    pub fn new_compiler_memory<'a>(&'a self) -> CompilerMemory<'a> {
        CompilerMemory{
            did_resolver: &*self.did_resolver,
            record_info: BTreeMap::default(),
            create_index: BTreeMap::default(),
            protocols: &self.protocols,
            sig_key: &self.agent_key.sig_key,
            key: &self.agent_key.enc_key,
        }
    }

    pub fn new_compiler<'a>(&'a self, mem: CompilerMemory<'a>) -> Compiler<'a> {
        Compiler::<'a>::new(mem, &self.router, &*self.did_resolver, self.tenant().clone())
    }
}
