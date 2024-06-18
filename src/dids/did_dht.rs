use super::error::Error;

use crate::common::Convert;
use crate::common::traits::KeyValueStore;
use crate::crypto::{ed25519, LocalKeyStore};
use crate::crypto::traits::{SecretKey as _};

pub use super::did_method::{DidMethod, IdentityKey};

use super::dns_packet::DhtDns;
use super::pkarr::PkarrRelay;
use super::did_core::{Method, Did, Url, Purpose, Service, DidKey, Keys, Type};

use serde::{Deserialize, Serialize};

const DEFAULT_GATEWAY_URI: &str = "https://diddht.tbddev.org";

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct DhtKey {
    key: DidKey,
}

impl IdentityKey for DhtKey {}

impl DhtKey {
    pub fn key(&self) -> &DidKey { &self.key }
    pub fn public_key(&self) -> ed25519::PublicKey {
        *self.key.public_key().clone().downcast::<ed25519::PublicKey>().unwrap()
    }

    pub fn new(public_key: ed25519::PublicKey, purposes: Vec<Purpose>, controller: Option<Did>) -> Result<Self, Error> {
        Ok(DhtKey{key: DidKey::new(Some("0".to_string()), Box::new(public_key), purposes, controller)?})
    }

    pub fn from_key(key: DidKey) -> Result<Self, Error> {
        if key.id() != "0" || !key.public_key().clone().downcast::<ed25519::PublicKey>().is_ok() {
            return Err(Error::Parse("DhtKey".to_string(), format!("{:?}", key)));
        }
        Ok(DhtKey{key})
    }

    pub fn generate_key() -> Result<(ed25519::SecretKey, DhtKey), Error> {
        let secret_key = ed25519::SecretKey::generate_key();
        let public_key = secret_key.public_key();
        Ok((secret_key, DhtKey{key: DidKey::new(
            Some("0".to_string()),
            public_key,
            vec![Purpose::Auth, Purpose::Asm, Purpose::Inv, Purpose::Del],
            None
        )?}))
    }
}


#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct DidDht {
    pub identity_key: DhtKey,
    pub also_known_as: Vec<Url>,
    pub controllers: Vec<Did>,
    pub services: Vec<Service>,
    pub keys: Keys,
    pub types: Vec<Type>
}

impl DidDht {
    pub fn new(
        identity_key: DhtKey,
        also_known_as: Vec<Url>,
        controllers: Vec<Did>,
        services: Vec<Service>,
        keys: Keys,
        types: Vec<Type>
    ) -> Self {
        DidDht{identity_key, also_known_as, controllers, services, keys, types}
    }
}

impl DidMethod for DidDht {
    fn method() -> Method { Method::DHT }
    fn id(&self) -> String {Convert::ZBase32.encode(&self.identity_key.key().public_key().to_vec())}
    fn keys(&self) -> Vec<&DidKey> { [vec![self.identity_key.key()], self.keys.keys()].concat()}

    fn get_key(&self, id: &str) -> Option<&DidKey> {
        self.keys.get(id)
    }

    fn create<KVS: KeyValueStore>(
        key_store: &mut LocalKeyStore<KVS>,
        also_known_as: Vec<Url>,
        controllers: Vec<Did>,
        services: Vec<Service>,
        keys: Keys,
        types: Vec<Type>
    ) -> Result<Self, Error> {
        let (secret, identity_key) = DhtKey::generate_key()?;
        key_store.store_key(&secret)?;
        Ok(DidDht{identity_key, also_known_as, controllers, services, keys, types})
    }

    async fn publish<KVS: KeyValueStore>(
        &self,
        key_store: &LocalKeyStore<KVS>,
        gateway: Option<Url>
    ) -> Result<(), Error> {
        let gateway = gateway.unwrap_or(Url::parse(DEFAULT_GATEWAY_URI)?);
        let public_key = self.identity_key.public_key();
        if let Some(secret_key) = key_store.get_key(&public_key)? {
            let id = self.id();
            let url = gateway.join(&id)?;
            PkarrRelay::put(
                url,
                DhtDns::to_bytes(self, vec![gateway])?,
                secret_key
            ).await
        } else { Err(Error::KeyNotFound()) }
    }

    async fn resolve(gateway: Option<Url>, id: &str) -> Result<Self, Error> {
        let gateway = gateway.unwrap_or(Url::parse(DEFAULT_GATEWAY_URI)?);
        let packet = PkarrRelay::get(gateway.join(id)?).await?;
        DhtDns::from_bytes(&packet[64+8..], id)
    }
}
