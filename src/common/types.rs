use super::error::Error;

pub trait KeyValueStore<K, V> {
    fn clear(&mut self) -> impl std::future::Future<Output = Result<(), Error>> + Send;
    fn close(&mut self) -> impl std::future::Future<Output = Result<(), Error>> + Send;
    fn delete(&mut self, key: K) -> impl std::future::Future<Output = Result<bool, Error>> + Send;
    fn get(&mut self, key: K) -> impl std::future::Future<Output = Result<Option<V>, Error>> + Send;
    fn set(&mut self, key: K, value: V) -> impl std::future::Future<Output = Result<(), Error>> + Send;
}
