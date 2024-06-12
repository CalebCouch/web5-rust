use super::error::Error;

pub trait KeyValueStore {
    fn default() -> Result<Self, Error> where Self: Sized;
    fn clear(&mut self) -> Result<(), Error>;
    fn close(&mut self) -> Result<(), Error>;
    fn delete(&mut self, key: &[u8]) -> Result<bool, Error>;
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Error>;
    fn set(&mut self, key: &[u8], value: &[u8]) -> Result<(), Error>;
}

pub trait KeyValueCache {
    fn default() -> Result<Self, Error> where Self: Sized;
    fn clear(&mut self) -> Result<(), Error>;
    fn close(&mut self) -> Result<(), Error>;
    fn delete(&mut self, key: &[u8]) -> Result<bool, Error>;
    fn get(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>, Error>;
    fn set(&mut self, key: &[u8], value: &[u8]) -> Result<(), Error>;
}
