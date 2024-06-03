use super::Error;
use super::traits::KeyValueStore;

use std::collections::HashMap;
use std::path::Path;

use leveldb::options::{Options,WriteOptions,ReadOptions};
use leveldb::database::Database;
use leveldb::snapshots::Snapshots;
use leveldb::iterator::Iterable;
use leveldb::kv::KV;

use serde_json::from_slice as deserialize;
use serde_json::to_vec as serialize;
use serde::{Serialize, Deserialize};

const PARTITION_KEY: &str = "__PARTITIONS__";

#[derive(Serialize, Deserialize, Debug)]
pub struct Partitions {
    paths: Vec<PathBuf>
}

pub struct LevelKey {
    key: Vec<u8>
}

impl db_key::Key for LevelKey {
    fn from_u8(key: &[u8]) -> Self {LevelKey{key: key.to_vec()}}
    fn as_slice<T, F: Fn(&[u8]) -> T>(&self, f: F) -> T {f(&self.key)}
}

pub struct LevelStore {
    db: Database<LevelKey>,
    pub location: PathBuf,
    partitions: HashMap<PathBuf, LevelStore>
}

impl std::fmt::Debug for LevelStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LevelStore[location: {}, partitions: {:#?}]", self.location, self.partitions)
    }
}

impl LevelStore {
    pub fn new_lvl(location: PathBuf) -> Result<LevelStore, Error> {
        std::fs::create_dir_all(location)?;
        let mut options = Options::new();
        options.create_if_missing = true;
        Ok(LevelStore{db: Database::open(location, options)?, location: location, partitions: HashMap::new()})
    }
}

impl KeyValueStore for LevelStore {
    fn new(location: PathBuf) -> Result<Self, Error> {
        let mut store = LevelStore::new_lvl(location)?;
        if let Some(partitions) = store.get(PARTITION_KEY.as_bytes())? {
            let partitions = deserialize::<Partitions>(&partitions)?;
            for path in partitions.paths {
                store.partition(&path)?;
            }
        } else {
            let partitions = Partitions{paths: vec![]};
            store.set(PARTITION_KEY.as_bytes(), &serialize(&partitions)?)?;
        }
        Ok(store)
    }
    fn partition(&mut self, path: PathBuf) -> Result<Box<&mut dyn KeyValueStore>, Error> {
        Ok(if self.partitions.get(&path)).is_some() {
            Box::new(self.partitions.get_mut(&path).unwrap())
        } else {
            let mut partitions = deserialize::<Partitions>(
                &self.get(PARTITION_KEY.as_bytes())?.unwrap()
            )?;
            if !partitions.paths.contains(&path) {
                partitions.paths.push(path.clone());
                self.set(PARTITION_KEY.as_bytes(), &serialize(&partitions)?)?;
            }
            self.partitions.insert(
                path.clone(),
                LevelStore::new(self.location.join(path.clone()))?
            );
            Box::new(self.partitions.get_mut(&path).unwrap())
        })
    }
    fn get_partition(&self, path: PathBuf) -> Option<Box<&dyn KeyValueStore>> {
        match self.partitions.get(&path) {None => None, Some(k) => Some(Box::new(k))}
    }
    fn clear(&mut self) -> Result<(), Error> {
        for part in self.partitions.values_mut() {
            part.clear()?;
        }
        let keys: Vec<Vec<u8>> = self.keys()?;
        for key in keys {
            self.db.delete(WriteOptions::new(), LevelKey{key: key})?;
        }
        Ok(())
    }
    fn delete(&mut self, key: &[u8]) -> Result<bool, Error> {
        let result = self.db.get(ReadOptions::new(), LevelKey{key: key.to_vec()})?.is_some();
        self.db.delete(WriteOptions::new(), LevelKey{key: key.to_vec()})?;
        Ok(result)
    }
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        Ok(self.db.get(ReadOptions::new(), LevelKey{key: key.to_vec()})?)
    }
    fn set(&mut self, key: &[u8], value: &[u8]) -> Result<(), Error> {
        Ok(self.db.put(WriteOptions::new(), LevelKey{key: key.to_vec()}, value)?)
    }

    fn get_all(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, Error> {
        Ok(self.db.snapshot().iter(ReadOptions::new()).map(|(k, v)| (k.key, v)).collect::<Vec<(Vec<u8>, Vec<u8>)>>()
            .into_iter().filter(|(k, _)| k != PARTITION_KEY.as_bytes()).collect())
    }

    fn keys(&self) -> Result<Vec<Vec<u8>>, Error> {
        Ok(self.get_all()?.into_iter().map(|(k, _)| k).collect())
    }

    fn values(&self) -> Result<Vec<Vec<u8>>, Error> {
        Ok(self.get_all()?.into_iter().map(|(_, v)| v).collect())
    }

    fn location(&self) -> &PathBuf { self.location }
}
