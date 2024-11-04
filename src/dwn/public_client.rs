use super::Error;

use simple_database::database::{Index, SortOptions, Filters};

use super::structs::{
    PublicCreateRequest,
    PublicUpdateRequest,
    PublicDeleteRequest,
    PublicReadRequest,
    ProtocolFetcher,
    PublicRecord,
    DwnRequest,
    Record,
    Action,
    Type
};

use super::traits::Router;
use simple_crypto::Hash;

use crate::dids::signing::{SignedObject, Signer, Verifier};
use crate::dids::{DidResolver, Did};

use std::collections::BTreeSet;

#[derive(Debug, Clone)]
pub struct PublicClient {
    signer: Signer,
    router: Box<dyn Router>,
    did_resolver: Box<dyn DidResolver>,
    protocol_fetcher: ProtocolFetcher,
}

impl PublicClient {
    pub fn new(
        signer: Signer,
        router: Box<dyn Router>,
        did_resolver: Box<dyn DidResolver>,
        protocol_fetcher: ProtocolFetcher,
    ) -> Self {
        PublicClient{signer, router, did_resolver, protocol_fetcher}
    }

    pub async fn create(
        &self,
        record: Record,
        index: Index,
        dids: &[&Did],
    ) -> Result<(), Error> {
        let request: PublicCreateRequest = PublicRecord::new(self.signer.clone(), record, index)?;
        let request = DwnRequest::new(Type::Public, Action::Create, serde_json::to_vec(&request)?);
        self.router.handle_request(&request, dids).await?;
        Ok(())
    }

    pub async fn read(
        &self,
        filters: Filters,
        sort_options: Option<SortOptions>,
        dids: &[&Did],
    ) -> Result<Vec<(Verifier, Record)>, Error> {
        let request: PublicReadRequest = (filters, sort_options);
        let request = DwnRequest::new(Type::Public, Action::Read, serde_json::to_vec(&request)?);
        let records: Vec<PublicRecord> = BTreeSet::from_iter(self.router.handle_request(&request, dids).await?.into_iter().flat_map(|data|
            serde_json::from_slice::<Vec<PublicRecord>>(&data).ok()
        ).flatten()).into_iter().collect();
        let mut results = Vec::new();

        //TODO ensure all records match the given filters

        for record in records {
            if let Ok(signer) = record.inner.verify(&*self.did_resolver, None).await {
                let (record, _) = record.inner.unwrap();
                if let Ok(protocol) = self.protocol_fetcher.get(&record.protocol) {
                    if record.validate(protocol).is_ok() {
                        results.push((signer, record));
                    }
                }
            }
        }

        Ok(results)
    }

    pub async fn update(
        &self,
        record: Record,
        index: Index,
        dids: &[&Did],
    ) -> Result<(), Error> {
        let request: PublicUpdateRequest = PublicRecord::new(self.signer.clone(), record, index)?;
        let request = DwnRequest::new(Type::Public, Action::Update, serde_json::to_vec(&request)?);
        self.router.handle_request(&request, dids).await?;
        Ok(())
    }

    pub async fn delete(
        &self,
        record_id: Hash,
        dids: &[&Did],
    ) -> Result<(), Error> {
        let request: PublicDeleteRequest = SignedObject::new(self.signer.clone(), record_id)?;
        let request = DwnRequest::new(Type::Public, Action::Delete, serde_json::to_vec(&request)?);
        self.router.handle_request(&request, dids).await?;
        Ok(())
    }
}
