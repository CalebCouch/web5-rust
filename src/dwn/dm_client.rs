use super::Error;

use super::structs::{
    DMCreateRequest,
    DMReadRequest,
    DwnRequest,
    DwnItem,
    Action,
    Type
};

use super::permission::PermissionSet;
use super::traits::Router;

use chrono::{DateTime, Utc};

use simple_crypto::SecretKey;

use crate::dids::signing::SignedObject;
use crate::dids::{DidResolver, DidKeyPair, Did};

use either::Either;

use std::collections::BTreeSet;

#[derive(Debug, Clone)]
pub struct DMClient {
    signer: DidKeyPair,
    com_key: SecretKey,
    router: Box<dyn Router>,
    did_resolver: Box<dyn DidResolver>,
}

impl DMClient {
    pub fn new(
        signer: DidKeyPair,
        com_key: SecretKey,
        router: Box<dyn Router>,
        did_resolver: Box<dyn DidResolver>,
    ) -> Self {
        DMClient{signer, com_key, router, did_resolver}
    }

    pub async fn create(
        &self,
        recipient: &Did,
        permission: PermissionSet,
    ) -> Result<(), Error> {
        let (_, rec_com_key) = self.did_resolver.resolve_dwn_keys(recipient).await?;
        let signed = SignedObject::from_keypair(&self.signer, permission)?;
        let payload = rec_com_key.encrypt(&serde_json::to_vec(&signed)?)?;
        let request: DMCreateRequest = DwnItem::new(rec_com_key, None, payload);
        let request = DwnRequest::new(Type::DM, Action::Create, serde_json::to_vec(&request)?);

        self.router.handle_request(&request, &[recipient]).await?;
        Ok(())
    }

    pub async fn read(
        &self,
        timestamp: DateTime<Utc>
    ) -> Result<Vec<(Did, PermissionSet)>, Error> {
        let request: DMReadRequest = SignedObject::from_key(&self.com_key, timestamp)?;
        let request = DwnRequest::new(Type::DM, Action::Read, serde_json::to_vec(&request)?);

        let items = BTreeSet::from_iter(self.router.handle_request(&request, &[&self.signer.public.did]).await?
            .into_iter().flat_map(|data|
                serde_json::from_slice::<Vec<DwnItem>>(&data).ok()
            ).flatten()
        ).into_iter().collect::<Vec<DwnItem>>();

        let mut results: Vec<(Did, PermissionSet)> = Vec::new();

        for item in items {
            if item.discover != self.com_key.public_key() || item.delete.is_some() {continue;}
            if let Ok(dc) = self.com_key.decrypt(&item.payload) {
                if let Ok(signed) = serde_json::from_slice::<SignedObject<PermissionSet>>(&dc) {
                    if let Ok(Either::Left(sender)) = signed.verify(&*self.did_resolver, None).await {
                        results.push((sender, signed.unwrap()));
                    }
                }
            }
        }
        Ok(results)
    }
}
