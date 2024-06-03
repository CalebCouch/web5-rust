use super::Error;

use super::structs::{DidMethod, Did, DidService, DidKey, DidType, DidKeyPurpose};
use super::traits::DidDocument;
use super::pkarr::PkarrRelay;
use super::dns_packet::DhtDns;

use crate::common::structs::Url;

use crate::crypto::ed25519::{SecretKey, PublicKey};
use crate::crypto::secp256k1::SecretKey as SPSecretKey;

use std::collections::BTreeMap;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

const DEFAULT_GATEWAY_URI: &str = "https://diddht.tbddev.org";

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct DhtDocument {
    pub id_key: PublicKey,
    pub also_known_as: Vec<Url>,
    pub controllers: Vec<Did>,
    pub services: BTreeMap<String, DidService>,
    pub keys: BTreeMap<String, DidKey>,
    pub types: Vec<DidType>
}

impl DhtDocument {
    pub fn new(
        id_key: PublicKey,
        also_known_as: Vec<Url>,
        controllers: Vec<Did>,
        services: BTreeMap<String, DidService>,
        keys: BTreeMap<String, DidKey>,
        types: Vec<DidType>
    ) -> Self {
        DhtDocument{id_key, also_known_as, controllers, services, keys, types}
    }

    pub async fn publish(
        &self,
        secret_key: &SecretKey,
    ) -> Result<(), Error> {
        let gateway = Url::from_str(DEFAULT_GATEWAY_URI)?;
        let id = self.id();
        let url = gateway.join(&id)?;
        PkarrRelay::put(
            url,
            DhtDns::to_bytes(self, vec![gateway])?,
            secret_key
        ).await
    }

    pub fn default(service_endpoints: Vec<String>) -> Result<(Self, SPSecretKey, SecretKey), Error> {
        let id_sec_key = SecretKey::new();
        let id_key = id_sec_key.public_key();

        let sec_key = SPSecretKey::new();
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
        Ok((doc, sec_key, id_sec_key))
    }
}

#[typetag::serde(name = "DHT")]
#[async_trait::async_trait]
impl DidDocument for DhtDocument {
    fn method(&self) -> DidMethod { DidMethod::DHT }
    fn id(&self) -> String {self.id_key.thumbprint()}

    fn keys(&self) -> Vec<&DidKey> { self.keys.values().collect() }
    fn services(&self) -> Vec<&DidService> { self.services.values().collect() }

    fn get_key(&self, id: &str) -> Option<&DidKey> { self.keys.get(id) }
    fn get_service(&self, id: &str) -> Option<&DidService> { self.services.get(id) }

    async fn resolve(id: &str) -> Result<Option<Self>, Error> {
      let gateway = Url::from_str(DEFAULT_GATEWAY_URI)?;
      PkarrRelay::get(gateway.join(id)?).await?
          .map(|p| DhtDns::from_bytes(&p[64+8..], id)).transpose()
    }
}
