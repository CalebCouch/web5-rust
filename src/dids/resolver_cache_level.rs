use crate::common::types::KeyValueStore;
use crate::common::error::Error as CommonError;
use crate::common::stores::LevelStore;
//use super::did_resolution::DidResolverCache;
use super::did_core::DidResolutionResult;
use super::error::Error;


use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};


#[derive(Deserialize, Serialize)]
pub struct CacheWrapper {
  exp: u64,
  value: DidResolutionResult
}

pub struct DidResolverCacheLevel {
    level_store: LevelStore,
    ttl: u64
}

impl DidResolverCacheLevel {
    pub fn new(level_store: Option<LevelStore>, location: Option<String>, ttl: Option<u64>) -> Result<DidResolverCacheLevel, Error> {
        let location = location.unwrap_or("DATA/DID_RESOLVERCACHE".to_string());
        //TODO: When would a level store ever be passed? Would it be a raw level db that needs to be built into a level store instead?
        let level_store = match level_store {
            Some(level_store) => level_store,
            None => {
                LevelStore::new(None, Some(location))?
            }
        };
        let ttl = ttl.unwrap_or(900000); //ttl: 15 minutes by default
        Ok(DidResolverCacheLevel{level_store, ttl})
    }
}

//TODO DidResolverCache
impl KeyValueStore<String, DidResolutionResult> for DidResolverCacheLevel {
    async fn clear(&mut self) -> Result<(), CommonError> {
        self.level_store.clear().await
    }
    async fn close(&mut self) -> Result<(), CommonError> {
        self.level_store.close().await
    }
    async fn delete(&mut self, key: String) -> Result<bool, CommonError> {
        self.level_store.delete(key).await
    }
    async fn get(&mut self, key: String) -> Result<Option<DidResolutionResult>, CommonError> {
        if let Some(bytes) = self.level_store.get(key.clone()).await? {
            let cache: CacheWrapper = serde_json::from_str(&String::from_utf8(bytes)?)?;
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() * 1000;
            if now >= cache.exp {
                self.delete(key).await?;
                Ok(None)
            } else {
                Ok(Some(cache.value))
            }
        } else {Ok(None)}
    }
    async fn set(&mut self, key: String, value: DidResolutionResult) -> Result<(), CommonError> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() * 1000;
        let cache = CacheWrapper{exp: now + self.ttl, value};
        self.level_store.set(key, serde_json::to_string(&cache)?.as_bytes().to_vec()).await
    }
}

