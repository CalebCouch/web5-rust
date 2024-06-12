use super::error::Error;
use crate::common::traits::{KeyValueStore, KeyValueCache};
use crate::common::stores::Cache;
use super::did_core::{DidUri, Url};
use super::did_method::DidMethod;
use serde::{Serialize, Deserialize};
use serde_json::to_vec as serialize;
use serde_json::from_slice as deserialize;

pub struct DidResolver<KVS: KeyValueStore> {
    cache: Cache<KVS>
}

impl<KVS: KeyValueStore> DidResolver<KVS> {
    pub fn new(kvs: Option<KVS>, ttl: Option<u64>) -> Result<Self, Error> {
        Ok(DidResolver{cache: Cache::<KVS>::new(kvs, ttl)?})
    }


    pub async fn resolve<M: DidMethod + Serialize + for<'a> Deserialize<'a> + Send>(&mut self, gateway: Option<Url>, did_uri: &DidUri) -> Result<M, Error> {
        let bytes = self.cache.get(&serialize(did_uri)?)?;
        Ok(match bytes {
            Some(bb) => {
                let m = deserialize::<M>(&bb)?;
                m
            },
            None => {
                let method: M = M::resolve(gateway, &did_uri.id).await?;
                self.cache.set(&serialize(did_uri)?, &serialize(&method)?)?;
                method
            }
        })
    }
}
