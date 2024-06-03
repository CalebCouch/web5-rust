use super::error::Error;
use super::traits::KeyValueStore;
use super::traits::{AsStorageBytes, FromStorageBytes};
use leveldb_rs::{DB, DBOptions};
use std::collections::HashMap;
use std::path::Path;


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
        let key = key.as_storage_bytes()?;
        let result = db.get(&key)?.is_some();
        db.delete(&key)?;
        Ok(result)
    }
    fn get(&self, key: &K) -> Result<Option<V>, Error> {
        Ok(self.db.as_ref().ok_or(Error::DataStore())?.get(&key.as_storage_bytes()?)?.as_ref().and_then(|v| V::from_storage_bytes(v).ok()))
    }
    fn set(&mut self, key: &K, value: &V) -> Result<(), Error> {
        Ok(self.db.as_mut().ok_or(Error::DataStore())?.put(&key.as_storage_bytes()?, &value.as_storage_bytes()?)?)
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
        Ok(self.store.remove(&key.as_storage_bytes()?).is_some())
    }
    fn get(&self, key: &K) -> Result<Option<V>, Error> {
        Ok(match self.store.get(&key.as_storage_bytes()?.to_vec()) {
            None => None,
            Some(v) => Some(V::from_storage_bytes(v)?)
        })
    }
    fn set(&mut self, key: &K, value: &V) -> Result<(), Error> {
        self.store.insert(key.as_storage_bytes()?.to_vec(), value.as_storage_bytes()?.to_vec());
        Ok(())
    }
}


