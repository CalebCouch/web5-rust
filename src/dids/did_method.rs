use super::error::Error;
use super::did_core::{Method, Did, Service, Keys, Url, Type, DidKey};

use crate::common::traits::KeyValueStore;
use crate::crypto::LocalKeyStore;
//use crate::crypto::common::Signer;

pub trait IdentityKey {}


pub trait DidMethod {
    fn method() -> Method;
    fn id(&self) -> String;
    fn did(&self) -> Did { Did::new(self.id(), Self::method()) }
    fn keys(&self) -> Vec<&DidKey>;
    fn get_key(&self, id: &str) -> Option<&DidKey>;

    fn create<KVS: KeyValueStore>(
        key_store: &mut LocalKeyStore<KVS>,
        also_known_as: Vec<Url>,
        controllers: Vec<Did>,
        services: Vec<Service>,
        keys: Keys,
        types: Vec<Type>
    ) -> Result<Self, Error> where Self: Sized;

    fn publish<KVS: KeyValueStore + Sync>(
        &self,
        key_store: &LocalKeyStore<KVS>,
        gateway: Option<Url>
    ) -> impl std::future::Future<Output = Result<(), Error>> + Send;


    fn resolve(gateway: Option<Url>, id: &str) -> impl std::future::Future<Output = Result<Self, Error>> + Send where Self: Sized;
}
