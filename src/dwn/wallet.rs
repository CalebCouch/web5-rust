use super::Error;

use crate::ed25519::SecretKey as EdSecretKey;
use simple_crypto::{PublicKey, Hashable, Hash};
use simple_database::database::{FiltersBuilder, Filter, IndexBuilder};

use crate::dids::structs::{Identity, DidKeyPair, Did};
use super::structs::{AgentKey, DwnKey, Record};
use super::Agent;

use super::protocol::Protocol;

use std::collections::BTreeMap;
use super::traits::Router;
use crate::dids::traits::DidResolver;


pub struct Wallet {
    _did_key: EdSecretKey,
    sig_key: DidKeyPair,
    enc_key: DwnKey,
    com_key: DwnKey,
    router: Option<Box<dyn Router>>,
    did_resolver: Option<Box<dyn DidResolver>>,
}

impl Wallet {
    pub fn new(
        identity: Identity,
        router: Option<Box<dyn Router>>,
        did_resolver: Option<Box<dyn DidResolver>>,
    ) -> Self {
        Wallet{
            _did_key: identity.did_key,
            sig_key: identity.sig_key,
            enc_key: DwnKey::new_root(identity.enc_key),
            com_key: DwnKey::new_root(identity.com_key),
            router,
            did_resolver,
        }
    }

    pub fn tenant(&self) -> &Did {&self.sig_key.public.did}

    pub async fn get_agent_key(&self, protocol: &Hash) -> Result<AgentKey, Error> {
        let root_agent_key = AgentKey::new(self.sig_key.clone(), self.enc_key.clone(), self.com_key.clone());
        let pf = Protocol::protocol_folder(protocol);
        let agent = Agent::new(root_agent_key, BTreeMap::from([(pf.hash(), pf.clone())]), self.router.clone(), self.did_resolver.clone());

        let record = Record::new(Some(*protocol), pf.hash(), Vec::new());
        agent.create(&[], None, record, &[self.tenant()]).await?;
        let filters = FiltersBuilder::build(vec![
            ("author", Filter::equal(self.tenant().to_string())),
            ("type", Filter::equal("agent_keys".to_string()))
        ]);
        let mut agent_keys = agent.public_read(filters, None, &[self.tenant()]).await?.first().and_then(|(_, record)|
            serde_json::from_slice::<Vec<PublicKey>>(&record.payload).ok()
        ).unwrap_or_default();

        let enc_key = self.enc_key.from_path(&[*protocol])?;
        if !agent_keys.contains(&enc_key.key.public_key()) {
            agent_keys.push(enc_key.key.public_key());
            let record = Record::new(None, Protocol::agent_keys().hash(), serde_json::to_vec(&agent_keys)?);
            let mut ib = IndexBuilder::new();
            ib.add("type", "agent_keys".to_string());
            agent.public_update(record, ib.finish(), &[self.tenant()]).await?;
        }
        Ok(AgentKey::new(self.sig_key.clone(), enc_key, self.com_key.clone()))
    }
}

impl std::fmt::Debug for Wallet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Wallet")
        .field("tenant", &self.tenant().to_string())
        .finish()
    }
}
