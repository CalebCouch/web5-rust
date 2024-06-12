use super::error::Error;

use crate::common::Convert;
use crate::common::traits::KeyValueStore;
use crate::crypto::ed25519::Ed25519;
use crate::crypto::traits::{CryptoAlgorithm, SecretKey as SecretKeyTrait};
use crate::crypto::{ed25519, LocalKeyStore};
use crate::crypto::common::GenericPublicKey;

pub use super::did_method::DidMethod;

use super::dns_packet::DhtDns;
use super::pkarr::PkarrRelay;
use super::did_core::{Method, Did, Url, Purpose, Service, Key, Type};


use serde::{Deserialize, Serialize};

const DEFAULT_GATEWAY_URI: &str = "https://diddht.tbddev.org";

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct DhtKey {
    pub public_key: ed25519::PublicKey,
    pub purposes: Vec<Purpose>,
    pub controller: Option<Did>
}

impl DhtKey {
    pub fn from_key(key: Key) -> Result<Self, Error> {
        let error = || Error::Parse("DhtKey".to_string(), format!("{:?}", key));
        if key.id != Some("0".to_string()) { return Err(error()); }
        if let GenericPublicKey::Ed(public_key) = key.public_key {
            Ok(DhtKey{public_key, purposes: key.purposes, controller: key.controller})
        } else { Err(error()) }
    }
}

impl DhtKey {
    pub fn to_key(&self) -> Key {
        Key{
            id: Some("0".to_string()),
            public_key: GenericPublicKey::Ed(self.public_key),
            purposes: self.purposes.clone(),
            controller: self.controller.clone()
        }
    }
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct DidDht {
    pub identity_key: DhtKey,
    pub also_known_as: Vec<Url>,
    pub controllers: Vec<Did>,
    pub services: Vec<Service>,
    pub keys: Vec<Key>,
    pub types: Vec<Type>
}

impl DidMethod for DidDht {
    fn method() -> Method { Method::DHT }
    fn id(&self) -> String {Convert::ZBase32.encode(self.identity_key.public_key.as_bytes())}

    fn new<KVS: KeyValueStore>(key_store: &mut LocalKeyStore<KVS>) -> Result<Self, Error> {
        Self::create(key_store, vec![], vec![], vec![], vec![], vec![])
    }

    fn create<KVS: KeyValueStore>(
        key_store: &mut LocalKeyStore<KVS>,
        also_known_as: Vec<Url>,
        controllers: Vec<Did>,
        services: Vec<Service>,
        keys: Vec<Key>,
        types: Vec<Type>
    ) -> Result<Self, Error> {
        let secret_key: ed25519::SecretKey = Ed25519::generate_key();
        let public_key: ed25519::PublicKey = secret_key.public_key();
        key_store.store_key(&secret_key)?;
        let identity_key = DhtKey{
            public_key,
            purposes: vec![Purpose::Auth, Purpose::Asm, Purpose::Inv, Purpose::Del],
            controller: None
        };
        Ok(DidDht{identity_key, also_known_as, controllers, services, keys, types})
    }

    async fn publish<KVS: KeyValueStore>(
        &self,
        key_store: &LocalKeyStore<KVS>,
        gateway: Option<Url>
    ) -> Result<(), Error> {
        let gateway = gateway.unwrap_or(Url::parse(DEFAULT_GATEWAY_URI)?);
        let public_key = self.identity_key.public_key;
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
