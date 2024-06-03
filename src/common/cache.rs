use super::Error;
use super::traits::KeyValueStore;

use std::time::{UNIX_EPOCH, SystemTime};
use std::path::PathBuf;

use serde_json::from_slice as deserialize;
use serde_json::to_vec as serialize;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct CacheWrapper {
  exp: u64,
  value: Vec<u8>
}

const DEFAULT_CACHE_TTL: u64 = 900000;

#[derive(Debug, Clone)]
pub struct Cache {
    store: Box<dyn KeyValueStore>,
    ttl: u64
}

impl Cache {
    pub fn new_cache<KVS: KeyValueStore + 'static>(location: PathBuf, ttl: Option<u64>) -> Result<Self, Error> {
        let kvs = Box::new(KVS::new(location)?);
        let ttl = ttl.unwrap_or(DEFAULT_CACHE_TTL);
        Ok(Cache{store: kvs, ttl})
    }

    pub fn clear(&mut self) -> Result<(), Error> {
        self.store.clear()
    }
    pub fn delete(&mut self, key: &[u8]) -> Result<(), Error> {
        self.store.delete(key)
    }
    pub fn get(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        if let Some(cache) = self.store.get(key)? {
            let cache = deserialize::<CacheWrapper>(&cache)?;
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() * 1000;
            if now >= cache.exp && self.ttl > 0 {
                self.store.delete(key)?;
            } else {
                return Ok(Some(cache.value));
            }
        }
        Ok(None)
    }

    pub fn set(&mut self, key: &[u8], value: &[u8]) -> Result<(), Error> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() * 1000;
        let value = CacheWrapper{exp: now+self.ttl, value: value.to_vec()};
        self.store.set(key, &serialize(&value)?)
    }
}

