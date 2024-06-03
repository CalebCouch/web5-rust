use super::error::Error;
use super::common::{PublicKey, SecretKey};
use crate::common::traits::KeyValueStore;

pub struct LocalKeyStore<KVS: KeyValueStore<PublicKey, SecretKey>> {
    store: KVS
}

impl<KVS: KeyValueStore<PublicKey, SecretKey>> LocalKeyStore<KVS> {
    pub fn new(kvs: Option<KVS>) -> Result<Self, Error> {
        if let Some(kvs) = kvs {
            return Ok(LocalKeyStore{store: kvs});
        }
        Ok(LocalKeyStore{store: KVS::default()?})
    }

    pub fn store_key(&mut self, secret_key: &SecretKey) -> Result<(), Error> {
        self.store.set(&secret_key.public_key(), secret_key)?;
        Ok(())
    }

    pub fn get_key(&self, public_key: &PublicKey) -> Result<Option<SecretKey>, Error> {
        Ok(self.store.get(public_key)?)
    }
}
