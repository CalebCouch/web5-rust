use super::error::Error;
use super::types::KeyValueStore;

use leveldb_rs::{DB, DBOptions};
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

impl KeyValueStore<String, Vec<u8>> for LevelStore {
    async fn clear(&mut self) -> Result<(), Error> {
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
    async fn close(&mut self) -> Result<(), Error> {
        self.db = None;
        Ok(())
    }
    async fn delete(&mut self, key: String) -> Result<bool, Error> {
        let db = self.db.as_mut().ok_or(Error::DataStore())?;
        let result = db.get(key.as_bytes())?.is_some();
        db.delete(key.as_bytes())?;
        Ok(result)
    }
    async fn get(&mut self, key: String) -> Result<Option<Vec<u8>>, Error> {
        Ok(self.db.as_mut().ok_or(Error::DataStore())?.get(key.as_bytes())?)
    }
    async fn set(&mut self, key: String, value: Vec<u8>) -> Result<(), Error> {
        Ok(self.db.as_mut().ok_or(Error::DataStore())?.put(key.as_bytes(), &value)?)
    }
}
