use super::Error;
use super::structs::{
    DidService,
    DidMethod,
    DidKeyUri,
    Endpoint,
    DidKey,
    Did
};
use simple_crypto::PublicKey;
use dyn_clone::{clone_trait_object, DynClone};
use std::collections::BTreeSet;
use std::str::FromStr;
use url::Url;

#[typetag::serde(tag = "type")]
#[async_trait::async_trait]
pub trait DidDocument: DynClone + std::fmt::Debug + Sync + Send {
    fn method(&self) -> DidMethod;
    fn id(&self) -> String;

    fn keys(&self) -> Vec<&DidKey>;
    fn services(&self) -> Vec<&DidService>;

    fn get_key(&self, id: &str) -> Option<&DidKey>;
    fn get_service(&self, id: &str) -> Option<&DidService>;

    async fn resolve(id: &str) -> Result<Option<Self>, Error> where Self: Sized;

    //Provided
    fn did(&self) -> Did { Did::new(self.method(), self.id()) }
}
clone_trait_object!(DidDocument);

#[async_trait::async_trait]
pub trait DidResolver: DynClone + std::fmt::Debug + Sync + Send {
    async fn resolve(&self, did: &Did) -> Result<Option<Box<dyn DidDocument>>, Error>;

    //Provided
    async fn resolve_key(&self, kid: &DidKeyUri) -> Result<Option<DidKey>, Error> {
        Ok(self.resolve(&kid.did()).await?.and_then(|doc|
            doc.get_key(&kid.id()).cloned()
        ))
    }
    async fn resolve_dwn_keys(&self, did: &Did) -> Result<(PublicKey, PublicKey), Error> {
        let doc = self.resolve(did).await?.ok_or(Error::not_found("DID Document"))?;
        let sig = doc.get_key("sig").cloned().ok_or(Error::not_found("Key with ID sig"))?.public_key;
        let com = doc.get_key("com").cloned().ok_or(Error::not_found("Key with ID com"))?.public_key;
        Ok((sig, com))
    }

    async fn get_endpoints(&self, dids: &[Did]) -> Result<Vec<Endpoint>, Error> {
        let mut result = Vec::new();
        for did in dids {
            let doc = self.resolve(did).await?.ok_or(Error::not_found("DID Document"))?;
            let service = &doc.get_service("dwn").ok_or(Error::not_found("DWN Service"))?;
            for s in &service.service_endpoints {
                if let Ok(did) = Did::from_str(s) {
                    result.append(&mut Box::pin(self.get_endpoints(&[did])).await?);
                } else if let Ok(url) = Url::from_str(s) {
                    result.push(Endpoint((*did).clone(), url));
                }
            }
        }
        Ok(BTreeSet::from_iter(result).into_iter().collect())
    }
}
clone_trait_object!(DidResolver);
