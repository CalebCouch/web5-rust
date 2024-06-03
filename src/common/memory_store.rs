use super::Error;
use super::traits::KeyValueStore;

use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Partitions {
    names: Vec<String>
}

#[derive(Clone)]
pub struct MemoryStore {
    store: HashMap<Vec<u8>, Vec<u8>>,
    location: PathBuf,
    partitions: HashMap<PathBuf, MemoryStore>
}

impl KeyValueStore for MemoryStore {
    fn new(location: PathBuf) -> Result<Self, Error> {
        Ok(MemoryStore{store: HashMap::new(), location, partitions: HashMap::new()})
    }

    fn partition(&mut self, paths: PathBuf) -> Result<&mut dyn KeyValueStore, Error> {
        let mut store = self;
        for path in paths.iter() {
            let path: PathBuf = path.into();
            if store.partitions.contains_key(&path) {
                store = store.partitions.get_mut(&path).unwrap();
            } else {
                store.partitions.insert(path.clone(), MemoryStore::new(store.location.join(path.clone()))?);
                store = store.partitions.get_mut(&path).unwrap();
            }
        }
        Ok(store)
    }

    fn get_partition(&self, paths: PathBuf) -> Option<&dyn KeyValueStore> {
        let mut store = self;
        for path in paths.iter() {
            let path: PathBuf = path.into();
            store = store.partitions.get(&path)?;
        }
        Some(*Box::<&dyn KeyValueStore>::new(store))
    }

    fn clear(&mut self) -> Result<(), Error> {
        self.partitions.clear();
        self.store.clear();
        Ok(())
    }
    fn delete(&mut self, key: &[u8]) -> Result<(), Error> {
        self.store.remove(key);
        Ok(())
    }
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        Ok(self.store.get(key).cloned())
    }
    fn set(&mut self, key: &[u8], value: &[u8]) -> Result<(), Error> {
        self.store.insert(key.to_vec(), value.to_vec());
        Ok(())
    }

    fn get_all(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, Error> {
        Ok(self.store.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
    }

    fn keys(&self) -> Result<Vec<Vec<u8>>, Error> {
        Ok(self.store.keys().cloned().collect())
    }

    fn values(&self) -> Result<Vec<Vec<u8>>, Error> {
        Ok(self.store.values().cloned().collect())
    }

    fn location(&self) -> PathBuf { self.location.clone() }
}

impl std::fmt::Debug for MemoryStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut fmt = f.debug_struct("MemoryStore");
        fmt
        .field("location", &self.location)
        .field("partitions", &self.partitions)
        .field("store",
            &self.store.iter().map(|(key, value)| {
                let hexk = hex::encode(key);
                let key = std::str::from_utf8(key).unwrap_or(&hexk);
                let hexv = hex::encode(value);
                let value = std::str::from_utf8(value).unwrap_or(&hexv);
                format!("key: {}, value: {}",
                    &key[0..std::cmp::min(key.len(), 100)],
                    &value[0..std::cmp::min(value.len(), 100)],
                )
            }).collect::<Vec<String>>()
        )
        .finish()
    }
}
