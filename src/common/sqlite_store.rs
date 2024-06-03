use super::Error;
use super::traits::KeyValueStore;

use super::database::MAIN;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::path::PathBuf;

use rusqlite::Connection;

use serde_json::from_slice as deserialize;
use serde_json::to_vec as serialize;
use serde::{Serialize, Deserialize};

const PARTITION_KEY: &str = "__PARTITIONS__";

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Partitions {
    paths: Vec<PathBuf>
}

#[derive(Clone)]
pub struct SqliteStore {
    db: Arc<Mutex<Connection>>,
    location: PathBuf,
    partitions: HashMap<PathBuf, Self>
}

impl std::fmt::Debug for SqliteStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(main) = self.partitions.get(&PathBuf::from(MAIN)) {
            write!(f,
                "SqliteDB[\n    location: {:?},\n    entries: {}\n]",
                self.location,
                main.values().ok().map(|a| a.len().to_string()).unwrap_or("Error".to_string())
            )
        } else {
            write!(f,
                "SqliteStore[\n    location: {:?},\n    entries: {}\n    partitions: {:#?}\n]",
                self.location,
                self.values().ok().map(|a| a.len().to_string()).unwrap_or("Error".to_string()),
                self.partitions
            )
        }
    }
}

impl SqliteStore {
    pub fn new_sql(location: PathBuf) -> Result<Self, Error> {
        std::fs::create_dir_all(location.clone())?;
        let db = Connection::open(location.join("kvs.db"))?;
        db.execute("CREATE TABLE if not exists kvs(key TEXT NOT NULL UNIQUE, value TEXT);", [])?;
        Ok(SqliteStore{db: Arc::new(Mutex::new(db)), location, partitions: HashMap::new()})
    }
}

impl KeyValueStore for SqliteStore {
    fn new(location: PathBuf) -> Result<Self, Error> {
        let mut store = SqliteStore::new_sql(location)?;
        if let Some(partitions) = store.get(PARTITION_KEY.as_bytes())? {
            let partitions = deserialize::<Partitions>(&partitions)?;
            for path in partitions.paths {
                store.partition(path)?;
            }
        } else {
            let partitions = Partitions{paths: vec![]};
            store.set(PARTITION_KEY.as_bytes(), &serialize(&partitions)?)?;
        }
        Ok(store)
    }
    fn partition(&mut self, paths: PathBuf) -> Result<&mut dyn KeyValueStore, Error> {
        let mut store = self;
        for path in paths.iter() {
            let path = path.into();
            if store.partitions.contains_key(&path) {
                store = store.partitions.get_mut(&path).unwrap();
            } else {
                let mut partitions = deserialize::<Partitions>(
                    &store.get(PARTITION_KEY.as_bytes())?.unwrap()
                )?;
                if !partitions.paths.contains(&path) {
                    partitions.paths.push(path.clone());
                    store.set(PARTITION_KEY.as_bytes(), &serialize(&partitions)?)?;
                }
                store.partitions.insert(
                    path.clone(),
                    SqliteStore::new(store.location().join(path.clone()))?
                );
                store = store.partitions.get_mut(&path).unwrap();
            }
        }
        Ok(*Box::new(store))
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
        for part in self.partitions.values_mut() {
            part.clear()?;
        }
        let keys: Vec<Vec<u8>> = self.keys()?;
        for key in keys {
            self.delete(&key)?;
        }
        Ok(())
    }
    fn delete(&mut self, key: &[u8]) -> Result<(), Error> {
        let error = Error::bad_request("SqliteStore.delete", "Mutex poisoned");
        self.db.lock().or(Err(error))?.execute("DELETE FROM kvs WHERE key = ?;", [hex::encode(key)])?;
        Ok(())
    }
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        let error = Error::bad_request("SqliteStore.get", "Mutex poisoned");
        let db = self.db.lock().or(Err(error))?;
        let mut stmt = db.prepare(&format!("SELECT value FROM kvs where key = \'{}\'", hex::encode(key)))?;
        let result = stmt.query_and_then([], |row| {
            let item: String = row.get(0)?;
            Ok(hex::decode(item)?)
        })?.collect::<Result<Vec<Vec<u8>>, Error>>()?;
        Ok(result.first().cloned())
    }
    fn set(&mut self, key: &[u8], value: &[u8]) -> Result<(), Error> {
        let error = Error::bad_request("SqliteStore.set", "Mutex poisoned");
        self.db.lock().or(Err(error))?.execute("
            INSERT INTO kvs(key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value;
        ", [hex::encode(key), hex::encode(value)])?;
        Ok(())
    }

    fn get_all(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, Error> {
        let error = Error::bad_request("SqliteStore.get_all", "Mutex poisoned");
        let db = self.db.lock().or(Err(error))?;
        let mut stmt = db.prepare("SELECT key, value FROM kvs")?;
        let result = stmt.query_and_then([], |row| {
            let key: String = row.get(0)?;
            let value: String = row.get(1)?;
            Ok((hex::decode(key)?, hex::decode(value)?))
        })?.collect::<Result<Vec<(Vec<u8>, Vec<u8>)>, Error>>()?
        .into_iter().filter(|(k, _)| k != PARTITION_KEY.as_bytes()).collect();
        Ok(result)
    }

    fn keys(&self) -> Result<Vec<Vec<u8>>, Error> {
        Ok(self.get_all()?.into_iter().map(|(k, _)| k).collect())
    }

    fn values(&self) -> Result<Vec<Vec<u8>>, Error> {
        Ok(self.get_all()?.into_iter().map(|(_, v)| v).collect())
    }

    fn location(&self) -> PathBuf { self.location.clone() }
}
