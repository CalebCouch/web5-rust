use super::error::Error;

pub trait KeyValueStore<K: AsStorageBytes + Send, V: AsStorageBytes + FromStorageBytes + Send> {
    fn default() -> Result<Self, Error> where Self: Sized;
    fn clear(&mut self) -> Result<(), Error>;
    fn close(&mut self) -> Result<(), Error>;
    fn delete(&mut self, key: &K) -> Result<bool, Error>;
    fn get(&self, key: &K) -> Result<Option<V>, Error>;
    fn set(&mut self, key: &K, value: &V) -> Result<(), Error>;
}

pub trait KeyValueCache<K: AsStorageBytes + Send, V: AsStorageBytes + FromStorageBytes + Send> {
    fn default() -> Result<Self, Error> where Self: Sized;
    fn clear(&mut self) -> Result<(), Error>;
    fn close(&mut self) -> Result<(), Error>;
    fn delete(&mut self, key: &K) -> Result<bool, Error>;
    fn get(&mut self, key: &K) -> Result<Option<V>, Error>;
    fn set(&mut self, key: &K, value: V) -> Result<(), Error>;
}

pub trait AsStorageBytes {
    fn as_storage_bytes(&self) -> Vec<u8>;
}
pub trait FromStorageBytes {
    fn from_storage_bytes(b: &[u8]) -> Result<Self, Error> where Self: Sized;
}
