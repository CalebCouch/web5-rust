use super::error::Error;
use super::traits::{KeyValueStore, KeyValueCache};
use super::traits::{AsStorageBytes, FromStorageBytes};
use leveldb_rs::{DB, DBOptions};
use std::collections::HashMap;
use std::path::Path;
use std::marker::PhantomData;

use std::time::{UNIX_EPOCH, SystemTime};

pub struct StorableData {
    data: Vec<u8>
}

impl AsStorageBytes for StorableData {
    fn as_storage_bytes(&self) -> Vec<u8> {
        self.data.clone()
    }
}

impl FromStorageBytes for StorableData {
    fn from_storage_bytes(b: &[u8]) -> Result<Self, Error> {
        Ok(StorableData{data: b.to_vec()})
    }
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

impl<K: AsStorageBytes + Send, V: FromStorageBytes + AsStorageBytes + Send> KeyValueStore<K, V> for LevelStore {
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
    fn delete(&mut self, key: &K) -> Result<bool, Error> {
        let db = self.db.as_mut().ok_or(Error::DataStore())?;
        let key = key.as_storage_bytes();
        let result = db.get(&key)?.is_some();
        db.delete(&key)?;
        Ok(result)
    }
    fn get(&self, key: &K) -> Result<Option<V>, Error> {
        Ok(self.db.as_ref().ok_or(Error::DataStore())?.get(&key.as_storage_bytes())?.as_ref().and_then(|v| V::from_storage_bytes(v).ok()))
    }
    fn set(&mut self, key: &K, value: &V) -> Result<(), Error> {
        Ok(self.db.as_mut().ok_or(Error::DataStore())?.put(&key.as_storage_bytes(), &value.as_storage_bytes())?)
    }
}

pub struct MemoryStore {
    store: HashMap<Vec<u8>, Vec<u8>>
}

impl<K: AsStorageBytes + Send, V: FromStorageBytes + AsStorageBytes + Send> KeyValueStore<K, V> for MemoryStore {
    fn default() -> Result<MemoryStore, Error> {
        Ok(MemoryStore{store: HashMap::new()})
    }
    fn clear(&mut self) -> Result<(), Error> {
        self.store.clear();
        Ok(())
    }
    fn close(&mut self) -> Result<(), Error> {Ok(())}
    fn delete(&mut self, key: &K) -> Result<bool, Error> {
        Ok(self.store.remove(&key.as_storage_bytes()).is_some())
    }
    fn get(&self, key: &K) -> Result<Option<V>, Error> {
        Ok(match self.store.get(&key.as_storage_bytes().to_vec()) {
            None => None,
            Some(v) => Some(V::from_storage_bytes(v)?)
        })
    }
    fn set(&mut self, key: &K, value: &V) -> Result<(), Error> {
        self.store.insert(key.as_storage_bytes().to_vec(), value.as_storage_bytes().to_vec());
        Ok(())
    }
}

pub struct CacheWrapper<V: AsStorageBytes + FromStorageBytes + Send> {
  exp: u64,
  value: V
}

impl<V: AsStorageBytes + FromStorageBytes + Send> AsStorageBytes for CacheWrapper<V> {
    fn as_storage_bytes(&self) -> Vec<u8> {
        [self.exp.to_be_bytes().to_vec(), self.value.as_storage_bytes()].concat()
    }
}

impl<V: AsStorageBytes + FromStorageBytes + Send> FromStorageBytes for CacheWrapper<V> {
    fn from_storage_bytes(b: &[u8]) -> Result<Self, Error> {
        if b.len() < 9 { return Err(Error::FromStorageBytes()); }
        Ok(CacheWrapper{
            exp: u64::from_be_bytes(b[..8].try_into()?),
            value: V::from_storage_bytes(&b[8..])?
        })
    }
}

const DEFAULT_CACHE_TTL: u64 = 900000;

pub struct Cache<
    K: AsStorageBytes + Send,
    V: AsStorageBytes + FromStorageBytes + Send,
    KVS: KeyValueStore<K, CacheWrapper<V>> + Sized
> {
    store: KVS,
    ttl: u64,
    key_type: PhantomData<K>,
    value_type: PhantomData<V>
}

impl<
    K: AsStorageBytes + Send,
    V: AsStorageBytes + FromStorageBytes + Send,
    KVS: KeyValueStore<K, CacheWrapper<V>> + Sized
> Cache<K, V, KVS> {
    pub fn new(kvs: Option<KVS>, ttl: Option<u64>) -> Result<Self, Error> {
        let kvs = kvs.unwrap_or(KVS::default()?);
        let ttl = ttl.unwrap_or(DEFAULT_CACHE_TTL);
        Ok(Cache{store: kvs, ttl, key_type: PhantomData, value_type: PhantomData})
    }
}

impl<
    K: AsStorageBytes + Send,
    V: FromStorageBytes + AsStorageBytes + Send,
    KVS: KeyValueStore<K, CacheWrapper<V>> + Sized
> KeyValueCache<K, V> for Cache<K, V, KVS> {
    fn default() -> Result<Cache<K, V, KVS>, Error> {
        Ok(Cache{store: KVS::default()?, ttl: DEFAULT_CACHE_TTL, key_type: PhantomData, value_type: PhantomData})
    }
    fn clear(&mut self) -> Result<(), Error> {
        self.store.clear()
    }
    fn close(&mut self) -> Result<(), Error> {
        self.store.close()
    }
    fn delete(&mut self, key: &K) -> Result<bool, Error> {
        self.store.delete(key)
    }
    fn get(&mut self, key: &K) -> Result<Option<V>, Error> {
        if let Some(cache) = self.store.get(key)? {
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() * 1000;
            if now >= cache.exp {
                self.store.delete(key)?;
            } else {
                return Ok(Some(cache.value));
            }
        }
        Ok(None)
    }
    fn set(&mut self, key: &K, value: V) -> Result<(), Error> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() * 1000;
        let value = CacheWrapper{exp: now+self.ttl, value: value};
        self.store.set(key, &value)
    }
}

