use super::error::Error;
use crate::crypto::{PublicKey, SecretKey};
use crate::common::traits::{KeyValueStore, AsStorageBytes, FromStorageBytes, KeyValueCache};
use crate::common::stores::{Cache, CacheWrapper};
use crate::common::Error as CommonError;
use super::did_core::{DidUri};
use super::did_method::DidMethod;
use std::marker::PhantomData;

pub struct StoredDid {
   data: Vec<u8>
}

impl<V: DidMethod + AsStorageBytes> From<V> for StoredDid {
    fn from(item: V) -> Self {
        StoredDid{data: item.as_storage_bytes()}
    }
}

impl AsStorageBytes for StoredDid {
    fn as_storage_bytes(&self) -> Vec<u8> {
        self.data.clone()
    }
}

impl FromStorageBytes for StoredDid {
    fn from_storage_bytes(b: &[u8]) -> Result<Self, CommonError> {
        Ok(StoredDid{data: b.to_vec()})
    }
}

pub struct DidResolverCache<KVS: KeyValueStore<DidUri, CacheWrapper<StoredDid>>> {
    store: Cache<DidUri, StoredDid, KVS>
}

impl<KVS: KeyValueStore<DidUri, CacheWrapper<StoredDid>>> DidResolverCache<KVS> {
    pub fn new(kvs: Option<KVS>, ttl: Option<u64>) -> Result<Self, Error> {
        Ok(DidResolverCache{store: Cache::<DidUri, StoredDid, KVS>::new(kvs, ttl)?})
    }

    pub fn cache(&mut self, did_uri: &DidUri, did: StoredDid) -> Result<(), Error> {
        self.store.set(did_uri, did)?;
        Ok(())
    }

    pub fn get(&mut self, did_uri: &DidUri) -> Result<Option<StoredDid>, Error> {
        Ok(self.store.get(did_uri)?)
    }
}

pub struct DidResolver<V: DidMethod + AsStorageBytes + FromStorageBytes, KVS: KeyValueStore<DidUri, CacheWrapper<StoredDid>>> {
    cache: Cache<DidUri, StoredDid, KVS>,
    value_type: PhantomData<V>
}

impl<V: DidMethod + AsStorageBytes + FromStorageBytes, KVS: KeyValueStore<DidUri, CacheWrapper<StoredDid>>> DidResolver<V, KVS> {
    pub fn cache(&mut self, did_uri: &DidUri, did: V) -> Result<(), Error> {
        self.cache.set(did_uri, StoredDid::from(did))?;
        Ok(())
    }

    pub fn get(&mut self, did_uri: &DidUri) -> Result<Option<V>, Error> {
        Ok(match self.cache.get(did_uri)? {
            None => None,
            Some(did) => Some(V::from_storage_bytes(&did.data)?)
        })
    }
}
