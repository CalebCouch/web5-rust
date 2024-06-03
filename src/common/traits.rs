use super::Error;

use super::database::Index;

use crate::crypto::traits::Hashable;

use std::path::PathBuf;

use dyn_clone::{clone_trait_object, DynClone};

type KeyValue = Vec<(Vec<u8>, Vec<u8>)>;

pub trait KeyValueStore: std::fmt::Debug + Send + Sync + DynClone {
    fn new(location: PathBuf) -> Result<Self, Error> where Self: Sized;
    fn partition(&mut self, path: PathBuf) -> Result<&mut dyn KeyValueStore, Error>;
    fn get_partition(&self, path: PathBuf) -> Option<&dyn KeyValueStore>;
    fn clear(&mut self) -> Result<(), Error>;
    fn delete(&mut self, key: &[u8]) -> Result<(), Error>;
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Error>;
    fn set(&mut self, key: &[u8], value: &[u8]) -> Result<(), Error>;

    fn get_all(&self) -> Result<KeyValue, Error>;
    fn keys(&self) -> Result<Vec<Vec<u8>>, Error>;
    fn values(&self) -> Result<Vec<Vec<u8>>, Error>;

    fn location(&self) -> PathBuf;
}
clone_trait_object!(KeyValueStore);

pub trait Indexable: Hashable {
    const PRIMARY_KEY: &'static str = "primary_key";
    const DEFAULT_SORT: &'static str = Self::PRIMARY_KEY;
    fn primary_key(&self) -> Vec<u8> {self.hash_bytes()}
    fn secondary_keys(&self) -> Index {Index::default()}
}

impl Indexable for Vec<u8> {}
