use super::error::Error;

//TODO: remove
pub use permission::PermissionSet;

mod permission;
pub use permission::{PermissionOptions, ChannelPermissionOptions};
mod structs;
pub use structs::{RecordPath, Record};
mod protocol;
pub use protocol::{ChannelProtocol, Protocol};
mod traits;
pub use traits::{Response, TypeDebug};

pub mod compiler;
pub mod scripts;

#[cfg(not(feature = "advanced"))]
mod commands;

#[cfg(feature = "advanced")]
pub mod commands;

pub use compiler::CompilerCache;

#[cfg(feature = "advanced")]
pub mod custom_commands {
    pub use super::traits::Command;
    pub use super::structs::Header;
    pub use uuid::Uuid;
    pub use super::compiler::CompilerMemory;
}

use compiler::Compiler;
use structs::{BoxCommand, PathedKey};

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

use simple_crypto::{SecretKey};

use serde::{Serialize, Deserialize};

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
    pub enc_key: PathedKey,
    com_key: PathedKey,
    //master_protocol: Hash,
}

pub struct Wallet {
    identity: Identity,
    did_resolver: Box<dyn DidResolver>,
    client: Box<dyn Client>
}

impl Wallet {
    pub fn new(
        identity: Identity,
        did_resolver: Box<dyn DidResolver>,
        client: Box<dyn Client>
    ) -> Self {
        Wallet{
            identity,
            did_resolver,
            client
        }
    }

    pub fn root(&self) -> AgentKey {
        AgentKey{sig_key: self.identity.sig_key.clone(), enc_key: self.identity.enc_key.clone(), com_key: self.identity.com_key.clone()}
    }

    pub fn get_agent_key(&self, path: RecordPath) -> Result<AgentKey, Error> {
        let enc_key = self.identity.enc_key.derive_path(path.as_slice())?;
        Ok(AgentKey{sig_key: self.identity.sig_key.clone(), enc_key, com_key: self.identity.com_key.clone()})
    }
}

#[derive(Clone)]
pub struct Agent {
    agent_key: AgentKey,
    did_resolver: Box<dyn DidResolver>,
    router: Router,
}

impl Agent {
    pub async fn new(
        agent_key: AgentKey,
        did_resolver: Box<dyn DidResolver>,
        client: Box<dyn Client>
    ) -> Result<Self, Error> {
        let router = Router::new(did_resolver.clone(), client);
        let path = agent_key.enc_key.path.clone();
        let agent = Agent{agent_key, did_resolver, router};
        let mut cache = CompilerCache::default();
        agent.process_commands(
            &mut cache, vec![Box::new(commands::Init::new(vec![path])) as BoxCommand]
        ).await?.remove(0).downcast::<()>()?;
        Ok(agent)
    }

    pub fn tenant(&self) -> &Did {&self.agent_key.sig_key.public.did}

    #[cfg(feature = "advanced")]
    pub fn new_compiler<'a>(&'a self, cache: &'a mut CompilerCache) -> Compiler<'a> {
        self.internal_new_compiler(cache)
    }

    fn internal_new_compiler<'a>(&'a self, cache: &'a mut CompilerCache) -> Compiler<'a> {
        Compiler::<'a>::new(
            cache,
            &*self.did_resolver,
            //&self.protocols,
            &self.agent_key.sig_key,
            &self.agent_key.enc_key,
            &self.agent_key.com_key,
            &self.router,
            self.tenant().clone()
        )
    }

    pub async fn process_commands<'a>(&'a self, cache: &'a mut CompilerCache, commands: Vec<BoxCommand>) -> Result<Vec<Box<dyn Response>>, Error> {
        let mut comp = self.internal_new_compiler(cache);
        for command in commands.into_iter() {
            comp.add_command(command, None).await?;
        }
        Ok(comp.compile().await.remove(0))
    }
}
