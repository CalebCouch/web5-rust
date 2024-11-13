use super::Error;

use super::request_builder::{DwnRequest, DwnItem};
use super::router::{DwnResponse, Packet};

use crate::dids::signing::Verifier;
use crate::dids::{
    DefaultDidResolver,
    DidKeyPurpose,
    DhtDocument,
    DidResolver,
    DidKeyPair,
    DidMethod,
    DidKey,
    Did
};


use crate::ed25519::SecretKey as EdSecretKey;

use simple_crypto::SecretKey;
//use simple_database::database::{FiltersBuilder, UuidKeyed, CmpType, Filter};
use simple_database::{KeyValueStore, Indexable, Database};



use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Serialize, Deserialize};
use futures::future;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ServerIdentity {
    did_key: EdSecretKey,
    com_key: DidKeyPair,
    sig_key: SecretKey
}

impl ServerIdentity {
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
            ServerIdentity{did_key, com_key, sig_key},
            DhtDocument::default(did_pub, sig_pub, com_pub, service_endpoints)?
        ))
    }
}

//pub type DM = UuidKeyed<DwnItem>;

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
        server_identity: ServerIdentity,
        data_path: Option<PathBuf>,
        did_resolver: Option<Box<dyn DidResolver>>,
    ) -> Result<Self, Error> {
        let data_path = data_path.unwrap_or(PathBuf::from("Dwn"));
        let did_resolver = did_resolver.unwrap_or(Box::new(
            DefaultDidResolver::new::<KVS>(Some(data_path.join("DefaultDidResolver"))).await?
        ));
        Ok(Dwn{
            com_key: server_identity.com_key,
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
                Ok::<(Uuid, DwnResponse), Error>((uuid, self.process_request(req).await?))
            })).await?))
        }
      //    if let Ok(packet) = serde_json::from_slice::<Packet>(&payload) {
      //        Box::pin(async move {self.process_packet(packet).await}).await
      //    } else if let Ok(req) = serde_json::from_slice::<DwnRequest>(&payload) {
      //        self.process_request(req).await?;
      //    } else {
      //        Error::bad_request("dwn.process_packet", "Packet Could not be proccessed").into()
      //    }
      //} else {
      //    todo!()
      //    //tokio::spawn(self.send_packet(self.did_resolver.clone(), packet));
      //    //return Ok(DwnResponse::new(303, "Forwarded", Vec::new()));
      //}
    }

    pub async fn process_request(&self, request: DwnRequest) -> Result<DwnResponse, Error> {
        Ok(match request {
            DwnRequest::CreatePrivate(item) => {
                if self.private_database.get::<DwnItem>(&item.primary_key()).await?.is_some() {
                    DwnResponse::Conflict
                } else {
                    self.private_database.set(&item).await?;
                    DwnResponse::Empty
                }
            },
            DwnRequest::ReadPrivate(signed) => {
                if let Ok(Verifier::Right(discover)) = signed.verify(&*self.did_resolver, None).await {
                    DwnResponse::ReadPrivate(self.private_database.get::<DwnItem>(&discover.to_vec()).await?)
                } else {DwnResponse::InvalidAuth("Signature".to_string())}

            },
            DwnRequest::UpdatePrivate(item) => {
                if let Ok(Verifier::Right(key)) = item.verify(&*self.did_resolver, None).await {
                    let item = item.unwrap();
                    if let Some(old_item) = self.private_database.get::<DwnItem>(&item.discover.to_vec()).await? {
                        if old_item.delete != Some(key) {
                            return Ok(DwnResponse::InvalidAuth("Delete".to_string()));
                        }
                    }
                    self.private_database.set(&item).await?;
                    DwnResponse::Empty
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
            }
        })
      //    Type::Public => {
      //        match &request.action {
      //            Action::Create => {
      //                let public_record = serde_json::from_slice::<PublicCreateRequest>(&request.payload)?;
      //                public_record.inner.verify(&*self.did_resolver, None).await?;
      //                if self.public_database.get::<PublicRecord>(&public_record.primary_key()).await?.is_some() {
      //                    return conflict();
      //                }
      //                self.public_database.set(&public_record).await?;
      //                empty_success()
      //            },
      //            Action::Read => {
      //                let (filters, sort_options) = serde_json::from_slice::<PublicReadRequest>(&request.payload)?;
      //                let results = Some(self.public_database.query::<PublicRecord>(&filters, sort_options).await?.0)
      //                    .filter(|i| !i.is_empty())
      //                    .map(|i| serde_json::to_vec(&i)).transpose()?;
      //                Ok(DwnResponse::new(200, "", results))
      //            },
      //            Action::Update => {
      //                let public_record = serde_json::from_slice::<PublicUpdateRequest>(&request.payload)?;
      //                let verifier = public_record.inner.verify(&*self.did_resolver, None).await?;
      //                if let Some(old_record) = self.public_database.get::<PublicRecord>(&public_record.primary_key()).await? {
      //                    if old_record.inner.verify(&*self.did_resolver, Some(&verifier)).await.is_err() {
      //                        return auth_failed();
      //                    }
      //                }
      //                self.public_database.set(&public_record).await?;
      //                empty_success()
      //            }
      //            Action::Delete => {
      //                let payload = serde_json::from_slice::<PublicDeleteRequest>(&request.payload)?;
      //                let verifier = payload.verify(&*self.did_resolver, None).await?;
      //                let primary_key = payload.inner().as_bytes();
      //                if let Some(old_record) = self.public_database.get::<PublicRecord>(primary_key).await? {
      //                    if old_record.inner.verify(&*self.did_resolver, Some(&verifier)).await.is_err() {
      //                        return auth_failed();
      //                    }
      //                    self.public_database.delete(primary_key).await?;
      //                }
      //                empty_success()


      //            }
      //        }
      //    },
      //    Type::DM => {
      //        match &request.action {
      //            Action::Create => {
      //                let item = serde_json::from_slice::<DMCreateRequest>(&request.payload)?;
      //                let dm = UuidKeyed::new(item);
      //                if self.dms_database.get::<DM>(&dm.primary_key()).await?.is_some() {
      //                    return conflict();
      //                }
      //                self.dms_database.set(&dm).await?;
      //                empty_success()
      //            },
      //            Action::Read => {
      //                let payload = serde_json::from_slice::<DMReadRequest>(&request.payload)?;
      //                if let Ok(Verifier::Right(key)) = payload.verify(&*self.did_resolver, None).await {
      //                    let timestamp = payload.unwrap();
      //                    let filters = FiltersBuilder::build(vec![
      //                        ("timestamp_stored", Filter::cmp(CmpType::GT, timestamp)),
      //                        ("discover", Filter::equal(key.to_vec()))
      //                    ]);
      //                    let results = Some(self.dms_database.query::<DM>(&filters, None).await?.0
      //                        .into_iter().map(|dm| dm.inner()).collect::<Vec<DwnItem>>())
      //                        .filter(|i| !i.is_empty())
      //                        .map(|i| serde_json::to_vec(&i)).transpose()?;
      //                    Ok(DwnResponse::new(200, "", results))
      //                } else {auth_failed()}
      //            },
      //            _ => Err(Error::err("DwnServer", "Unsupported method for DMs"))
      //        }
      //    }
      //}
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
