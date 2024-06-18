use super::error::Error;
use super::traits::{PublicKey, SecretKey, AmbiguousKey};
use crate::common::traits::KeyValueStore;
use super::{ed25519, secp256k1, secp256r1};
use super::common::Curve;

pub struct LocalKeyStore<KVS: KeyValueStore> {
    store: KVS
}

impl<KVS: KeyValueStore, > LocalKeyStore<KVS> {
    pub fn new(kvs: Option<KVS>) -> Result<Self, Error> {
        let kvs = kvs.unwrap_or(KVS::default()?);
        Ok(LocalKeyStore{store: kvs})
    }

    pub fn store_key<V: SecretKey>(&mut self, secret_key: &V) -> Result<(), Error> {
        self.store.set(&secret_key.public_key().to_vec(), &secret_key.to_vec())?;
        Ok(())
    }

    pub fn get_key<K: PublicKey, V: SecretKey>(&self, public_key: &K) -> Result<Option<V>, Error> {
        Ok(match self.store.get(&public_key.to_vec())? {
            None => None,
            Some(b) => Some(V::from_bytes(&b)?)
        })
    }

    pub fn get_dyn_key(&self, public_key: &Box<dyn PublicKey>) -> Result<Option<Box<dyn SecretKey>>, Error> {
        Ok(match self.store.get(&public_key.to_vec())? {
            None => None,
            Some(b) => {
                Some(match public_key.curve() {
                    Curve::Ed => Box::new(ed25519::SecretKey::from_bytes(&b)?),
                    Curve::K1 => Box::new(secp256k1::SecretKey::from_bytes(&b)?),
                    Curve::R1 => Box::new(secp256r1::SecretKey::from_bytes(&b)?)
                })
            }
        })
    }
}
