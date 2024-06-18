use super::error::Error;
use super::traits::{KeyValueStore, KeyValueCache};
use leveldb_rs::{DB, DBOptions};
use std::collections::HashMap;
use std::path::Path;

use serde::{Serialize, Deserialize};
use std::time::{UNIX_EPOCH, SystemTime};
use serde_json::to_vec as serialize;
use serde_json::from_slice as deserialize;

#[derive(Serialize, Deserialize)]
pub struct StorableData {
    data: Vec<u8>
}

pub struct LevelStore {
    db: Option<DB>,
    pub location: String,
}

impl LevelStore {
    pub fn new(db: Option<DB>, location: Option<String>) -> Result<LevelStore, Error> {
        let location = location.unwrap_or("DATASTORE".to_string());
        let db = match db {
            Some(db) => db,
            None => {
                let mut options = DBOptions::new().ok_or(Error::DataStore())?;
                options.set_create_if_missing(true);
                DB::open_with_opts(Path::new(&location), options)?
            }
        };
        Ok(LevelStore{db: Some(db), location})
    }
}

impl KeyValueStore for LevelStore {
    fn default() -> Result<LevelStore, Error> {
        LevelStore::new(None, None)
    }
    fn clear(&mut self) -> Result<(), Error> {
        let db = self.db.as_mut().ok_or(Error::DataStore())?;
        let keys: Vec<Vec<u8>> = db.iter()?
        .alloc()
        .map(|kv| kv.0)
        .collect();
        for key in keys {
            db.delete(&key)?;
        }
        Ok(())
    }
    fn close(&mut self) -> Result<(), Error> {
        self.db = None;
        Ok(())
    }
    fn delete(&mut self, key: &[u8]) -> Result<bool, Error> {
        let db = self.db.as_mut().ok_or(Error::DataStore())?;
        let result = db.get(key)?.is_some();
        db.delete(key)?;
        Ok(result)
    }
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        Ok(self.db.as_ref().ok_or(Error::DataStore())?.get(key)?)
    }
    fn set(&mut self, key: &[u8], value: &[u8]) -> Result<(), Error> {
        Ok(self.db.as_mut().ok_or(Error::DataStore())?.put(key, value)?)
    }
}

pub struct MemoryStore {
    store: HashMap<Vec<u8>, Vec<u8>>
    //partitions: HashMap<String, MemoryStore>
}

impl KeyValueStore for MemoryStore {
    fn default() -> Result<MemoryStore, Error> {
        //, partitions: HashMap::new()
        Ok(MemoryStore{store: HashMap::new()})
    }
    fn clear(&mut self) -> Result<(), Error> {
        self.store.clear();
        Ok(())
    }
    fn close(&mut self) -> Result<(), Error> {Ok(())}
    fn delete(&mut self, key: &[u8]) -> Result<bool, Error> {
        Ok(self.store.remove(key).is_some())
    }
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        Ok(self.store.get(key).cloned())
    }
    fn set(&mut self, key: &[u8], value: &[u8]) -> Result<(), Error> {
        self.store.insert(key.to_vec(), value.to_vec());
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
pub struct CacheWrapper {
  exp: u64,
  value: Vec<u8>
}

const DEFAULT_CACHE_TTL: u64 = 900000;

pub struct Cache<KVS: KeyValueStore + Sized> {
    store: KVS,
    ttl: u64
}

impl<KVS: KeyValueStore + Sized> Cache<KVS> {
    pub fn new(kvs: Option<KVS>, ttl: Option<u64>) -> Result<Self, Error> {
        let kvs = kvs.unwrap_or(KVS::default()?);
        let ttl = ttl.unwrap_or(DEFAULT_CACHE_TTL);
        Ok(Cache{store: kvs, ttl})
    }
}

impl<KVS: KeyValueStore + Sized> KeyValueCache for Cache<KVS> {
    fn default() -> Result<Self, Error> {
        Ok(Cache{store: KVS::default()?, ttl: DEFAULT_CACHE_TTL})
    }
    fn clear(&mut self) -> Result<(), Error> {
        self.store.clear()
    }
    fn close(&mut self) -> Result<(), Error> {
        self.store.close()
    }
    fn delete(&mut self, key: &[u8]) -> Result<bool, Error> {
        self.store.delete(key)
    }
    fn get(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        if let Some(cache) = self.store.get(key)? {
            let cache = deserialize::<CacheWrapper>(&cache)?;
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() * 1000;
            if now >= cache.exp {
                self.store.delete(key)?;
            } else {
                return Ok(Some(cache.value));
            }
        }
        Ok(None)
    }
    fn set(&mut self, key: &[u8], value: &[u8]) -> Result<(), Error> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() * 1000;
        let value = CacheWrapper{exp: now+self.ttl, value: value.to_vec()};
        self.store.set(key, &serialize(&value)?)
    }
}

