use super::error::Error;
use super::did_core::{Method, Did, Service, Key, Url, Type};

use crate::common::traits::KeyValueStore;
use crate::crypto::{LocalKeyStore, PublicKey, SecretKey};


pub trait DidMethod {
    fn method() -> Method;

    fn id(&self) -> String;

    fn new<KVS: KeyValueStore<PublicKey, SecretKey>>(key_store: &mut LocalKeyStore<KVS>) -> Result<Self, Error> where Self: Sized;

    fn create<KVS: KeyValueStore<PublicKey, SecretKey>>(
        key_store: &mut LocalKeyStore<KVS>,
        also_known_as: Vec<Url>,
        controllers: Vec<Did>,
        services: Vec<Service>,
        keys: Vec<Key>,
        types: Vec<Type>
    ) -> Result<Self, Error> where Self: Sized;

    fn publish<KVS: KeyValueStore<PublicKey, SecretKey> + Sync>(
        &self,
        key_store: &LocalKeyStore<KVS>,
        gateway: Option<Url>
    ) -> impl std::future::Future<Output = Result<(), Error>> + Send;


    fn resolve(gateway: Option<Url>, id: String) -> impl std::future::Future<Output = Result<Self, Error>> + Send where Self: Sized;
}
