pub mod structs;
pub mod traits;
pub mod router;
pub mod json_rpc;

use super::Error;

use crate::ed25519::SecretKey as EdSecretKey;
use crate::dids::signing::Verifier;
use crate::dids::{
    DefaultDidResolver,
    DidResolver,
    DidKeyPurpose,
    DhtDocument,
    DidKeyPair,
    DidMethod,
    DidKey,
    Did
};

use structs::{
    PublicDwnItem,
    DwnResponse,
    DwnRequest,
    DwnItem,
    Packet,
};

use std::collections::BTreeMap;
use std::path::PathBuf;

use simple_crypto::SecretKey;
use simple_database::{KeyValueStore, Indexable, Database};
use simple_database::database::{Filters, Filter, UuidKeyed, CmpType};

use serde::{Serialize, Deserialize};
use futures::future;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct DwnIdentity {
    did_key: EdSecretKey,
    com_key: DidKeyPair,
    sig_key: SecretKey
}

impl DwnIdentity {
    pub async fn publish_doc(&self, document: &DhtDocument) -> Result<(), Error> {
        document.publish(&self.did_key).await
    }
    pub fn new(service_endpoints: Vec<String>) -> Result<(Self, DhtDocument), Error> {
        let did_key = EdSecretKey::new();
        let did_pub = did_key.public_key();
        let com = SecretKey::new();
        let com_pub = com.public_key();
        let com_key = DidKeyPair::new(com, DidKey::new(
            Some("com".to_string()),
            Did::new(DidMethod::DHT, did_key.public_key().thumbprint()),
            com_pub.clone(),
            vec![DidKeyPurpose::Auth, DidKeyPurpose::Asm, DidKeyPurpose::Agm],
            None
        )).unwrap();
        let sig_key = SecretKey::new();
        let sig_pub = sig_key.public_key();
        Ok((
            DwnIdentity{did_key, com_key, sig_key},
            DhtDocument::default(did_pub, sig_pub, com_pub, service_endpoints)?
        ))
    }
}

#[derive(Clone)]
pub struct Dwn {
    pub com_key: DidKeyPair,
    pub private_database: Database,
    pub public_database: Database,
    pub dms_database: Database,
    pub did_resolver: Box<dyn DidResolver>,
}

impl Dwn {
    pub async fn new<KVS: KeyValueStore + 'static>(
        dwn_identity: DwnIdentity,
        data_path: Option<PathBuf>,
        did_resolver: Option<Box<dyn DidResolver>>,
    ) -> Result<Self, Error> {
        let data_path = data_path.unwrap_or(PathBuf::from("Dwn"));
        let did_resolver = did_resolver.unwrap_or(Box::new(
            DefaultDidResolver::new::<KVS>(Some(data_path.join("DefaultDidResolver"))).await?
        ));
        Ok(Dwn{
            com_key: dwn_identity.com_key,
            private_database: Database::new::<KVS>(data_path.join("DATABASE").join("PRIVATE")).await?,
            public_database: Database::new::<KVS>(data_path.join("DATABASE").join("PUBLIC")).await?,
            dms_database: Database::new::<KVS>(data_path.join("DATABASE").join("DMS")).await?,
            did_resolver,
        })
    }

    pub async fn process_packet(
        &self, packet: Packet
    ) -> Result<BTreeMap<Uuid, DwnResponse>, Error> {
        if packet.recipient != self.com_key.public.did {
            Err(Error::bad_request("Packet Not Addressed To Tenant"))
        } else {
            let payload = self.com_key.secret.decrypt(&packet.payload)?;
            let reqs = serde_json::from_slice::<BTreeMap<Uuid, DwnRequest>>(&payload)?;
            Ok(BTreeMap::from_iter(future::try_join_all(reqs.into_iter().map(|(uuid, req)| async move {
                let response = self.process_request(req).await;
                if let Err(e) = &response {println!("Error: {}", e)}
                Ok::<(Uuid, DwnResponse), Error>((uuid, response?))
            })).await?))
        }
    }

    pub async fn process_request(&self, request: DwnRequest) -> Result<DwnResponse, Error> {
        Ok(match request {
            DwnRequest::CreatePrivate(dis_signed) => {
                let discover = &dis_signed.inner().discover;
                if dis_signed.verify(&*self.did_resolver, Some(&Verifier::Right(discover.clone()))).await.is_ok() {
                    let item = dis_signed.unwrap();
                    if let Some(old_item) = self.private_database.get::<DwnItem>(&item.primary_key()).await? {
                        DwnResponse::Conflict(old_item)
                    } else {
                        self.private_database.set(&item).await?;
                        DwnResponse::Empty
                    }
                } else {DwnResponse::InvalidAuth("Signature".to_string())}
            },
            DwnRequest::ReadPrivate(signed) => {
                if let Ok(Verifier::Right(discover)) = signed.verify(&*self.did_resolver, None).await {
                    DwnResponse::ReadPrivate(self.private_database.get::<DwnItem>(&discover.to_vec()).await?)
                } else {DwnResponse::InvalidAuth("Signature".to_string())}

            },
            DwnRequest::UpdatePrivate(del_signed) => {
                if let Ok(Verifier::Right(key)) = del_signed.verify(&*self.did_resolver, None).await {
                    let dis_signed = del_signed.unwrap();
                    let discover = &dis_signed.inner().discover;
                    if dis_signed.verify(&*self.did_resolver, Some(&Verifier::Right(discover.clone()))).await.is_ok() {
                        let item = dis_signed.unwrap();
                        if let Some(old_item) = self.private_database.get::<DwnItem>(&item.discover.to_vec()).await? {
                            if old_item.delete != Some(key) {
                                return Ok(DwnResponse::InvalidAuth("Delete".to_string()));
                            }
                        }
                        self.private_database.set(&item).await?;
                        DwnResponse::Empty
                    } else {DwnResponse::InvalidAuth("Signature".to_string())}
                } else {DwnResponse::InvalidAuth("Signature".to_string())}
            },
            DwnRequest::DeletePrivate(discover) => {
                if let Ok(Verifier::Right(delete)) = discover.verify(&*self.did_resolver, None).await {
                    let discover = discover.unwrap();
                    if let Some(old_item) = self.private_database.get::<DwnItem>(&discover.to_vec()).await? {
                        if old_item.delete != Some(delete) {
                            return Ok(DwnResponse::InvalidAuth("Delete".to_string()));
                        }
                        self.private_database.delete(&discover.to_vec()).await?;
                    }
                    DwnResponse::Empty
                } else {DwnResponse::InvalidAuth("Signature".to_string())}
            },
            DwnRequest::CreatePublic(item) => {
                if item.0.verify(&*self.did_resolver, None).await.is_ok() {
                    if let Some(item) = self.public_database.get::<PublicDwnItem>(&item.primary_key()).await? {
                        return Ok(DwnResponse::PublicConflict(item));
                    }
                    self.public_database.set(&item).await?;
                    DwnResponse::Empty
                } else {DwnResponse::InvalidAuth("Signature".to_string())}
            },
            DwnRequest::ReadPublic(filters, sort_options) => {
                DwnResponse::ReadPublic(self.public_database.query::<PublicDwnItem>(&filters, sort_options).await?.0)
            },
            DwnRequest::UpdatePublic(item) => {
                if let Ok(verifier) = item.0.verify(&*self.did_resolver, None).await {
                    if let Some(oitem) = self.public_database.get::<PublicDwnItem>(&item.primary_key()).await? {
                        if verifier != *oitem.0.signer() {
                            return Ok(DwnResponse::InvalidAuth("Signature".to_string()));
                        }
                    }
                    self.public_database.set(&item).await?;
                    DwnResponse::Empty
                } else {DwnResponse::InvalidAuth("Signature".to_string())}
            },
            DwnRequest::DeletePublic(req) => {
                if let Ok(verifier) = req.verify(&*self.did_resolver, None).await {
                    if let Some(item) = self.public_database.get::<PublicDwnItem>(req.inner().as_bytes()).await? {
                        if verifier != *item.0.signer() {
                            return Ok(DwnResponse::InvalidAuth("Signature".to_string()));
                        }
                    }
                    DwnResponse::Empty
                } else {DwnResponse::InvalidAuth("Signature".to_string())}
            },
            DwnRequest::CreateDM(item) => {
                let dm = UuidKeyed::new(item);
                self.dms_database.set(&dm).await?;
                DwnResponse::Empty
            },
            DwnRequest::ReadDM(timestamp) => {
                if let Ok(Verifier::Right(key)) = timestamp.verify(&*self.did_resolver, None).await {
                    let timestamp = timestamp.unwrap();
                    let filters = Filters::new(vec![
                        ("timestamp_stored", Filter::cmp(CmpType::GT, timestamp)),
                        ("discover", Filter::equal(key.to_vec()))
                    ]);
                    DwnResponse::ReadDM(self.dms_database.query::<UuidKeyed<DwnItem>>(&filters, None).await?.0.into_iter().map(|dm| dm.inner()).collect::<Vec<DwnItem>>())
                } else {DwnResponse::InvalidAuth("Signature".to_string())}
            }
        })
    }

    pub async fn debug(&self) -> Result<String, Error> {
        Ok(
            self.com_key.public.did.to_string()+"\n"+
            &self.private_database.debug().await?+
            &self.public_database.debug().await?+
            &self.dms_database.debug().await?
        )
    }
}

impl std::fmt::Debug for Dwn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut fmt = f.debug_struct("Dwn");
        fmt.field("tenant", &self.com_key.public.did.to_string())
        .field("private_database", &self.private_database)
        .field("public_database", &self.public_database)
        .field("dms", &self.dms_database)
        .finish()
    }
}
