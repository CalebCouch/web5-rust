use super::error::Error;
use super::traits::{PublicKey, SecretKey};
use crate::common::traits::KeyValueStore;
use serde_json::to_vec as serialize;
use serde::Serialize;

pub struct LocalKeyStore<KVS: KeyValueStore> {
    store: KVS
}

impl<KVS: KeyValueStore, > LocalKeyStore<KVS> {
    pub fn new(kvs: Option<KVS>) -> Result<Self, Error> {
        let kvs = kvs.unwrap_or(KVS::default()?);
        Ok(LocalKeyStore{store: kvs})
    }

    pub fn store_key<K: PublicKey + Serialize, V: SecretKey<K>>(&mut self, secret_key: &V) -> Result<(), Error> {
        self.store.set(&serialize(&secret_key.public_key())?, secret_key.as_bytes())?;
        Ok(())
    }

    pub fn get_key<K: PublicKey + Serialize, V: SecretKey<K>>(&self, public_key: &K) -> Result<Option<V>, Error> {
        Ok(match self.store.get(&serialize(&public_key)?)? {
            None => None,
            Some(b) => Some(V::from_bytes(&b)?)
        })
    }
}
