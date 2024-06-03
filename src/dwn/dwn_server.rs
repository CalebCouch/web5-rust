use super::Error;

use super::structs::{
    DwnItem,
    CreateRequest,
    ReadRequest,
    ReadDMRequest,
    UpdateRequest,
    DeleteRequest,
    DwnResponse,
    DwnRequest,
    Packet,
    Action,
};

use crate::common::database::{FiltersBuilder, UuidKeyed, CmpType, Filter};
use crate::common::traits::{KeyValueStore, Indexable};
use crate::common::Database;

use crate::crypto::secp256k1::SecretKey;

use crate::dids::structs::{Did, DidResolver as DefaultDidResolver};
use crate::dids::traits::DidResolver;
use crate::dids::signing::Verifier;

use std::path::PathBuf;

const DMS: &str = "DMS";
pub type DM = UuidKeyed<DwnItem>;

pub struct DwnServer {
    pub did: Did,
    pub key: SecretKey,
    pub database: Database,
    pub did_resolver: Box<dyn DidResolver>,
}

impl DwnServer {
    pub fn new<KVS: KeyValueStore + 'static>(
        data_path: Option<PathBuf>,
        did: Did,
        key: SecretKey,
        did_resolver: Option<Box<dyn DidResolver>>,
    ) -> Result<Self, Error> {
        let data_path = data_path.unwrap_or(PathBuf::from("DWN"));
        let did_resolver = did_resolver.unwrap_or(Box::new(DefaultDidResolver::new()));
        Ok(DwnServer{
            did,
            key,
            database: Database::new::<KVS>(data_path.join("DATABASE"))?,
            did_resolver,
        })
    }

    pub async fn process_packet(&mut self, packet: Packet) -> Result<DwnResponse, Error> {
        if packet.recipient == self.did {
            let payload = self.key.decrypt(&packet.payload)?;
            if let Ok(packet) = serde_json::from_slice::<Packet>(&payload) {
                Box::pin(async move {self.process_packet(packet).await}).await
            } else if let Ok(req) = serde_json::from_slice::<DwnRequest>(&payload) {
                Ok(match self.process_request(req).await {
                    Ok(res) => res,
                    Err(e) => Into::<DwnResponse>::into(e)
                })
            } else {
                Ok(Error::bad_request("dwn.process_packet", "packet.payload was not another packet or messages").into())
            }
        } else {
            todo!()
            //tokio::spawn(self.send_packet(self.did_resolver.clone(), packet));
            //return Ok(DwnResponse::new(303, "Forwarded", Vec::new()));
        }
    }

    pub async fn process_request(&mut self, request: DwnRequest) -> Result<DwnResponse, Error> {
        let ec = "dwn.process_request";
        let conflict = || Err(Error::conflict(ec, "Payload with given discover key already exists"));
        let auth_failed = || Err(Error::auth_failed(ec, "Request could not be authorized"));
        let empty_success = || Ok(DwnResponse::new(200, "", None));

        match &request.action {
            Action::Create => {
                let item = serde_json::from_slice::<CreateRequest>(&request.payload)?;
                if request.dm {
                    let dm = UuidKeyed{inner: item};
                    if self.database.get::<DM>(Some(PathBuf::from(DMS)), &dm.primary_key())?.is_some() {
                        return conflict();
                    }
                    self.database.set(Some(PathBuf::from(DMS)), &dm)?;
                } else {
                    if self.database.get::<DwnItem>(None, &item.primary_key())?.is_some() {
                        return conflict();
                    }
                    self.database.set(None, &item)?;
                }
                empty_success()
            },
            Action::Read => {
                let results = if request.dm {
                    let payload = serde_json::from_slice::<ReadDMRequest>(&request.payload)?;
                    if let Ok((Verifier::Right(key), timestamp)) = payload.verify(&*self.did_resolver, None).await {
                        let filters = FiltersBuilder::build(vec![
                            ("timestamp_stored", Filter::cmp(CmpType::GT, timestamp)),
                            ("discover", Filter::equal(key.to_vec()))
                        ]);
                        let results = self.database.query::<DM>(Some(PathBuf::from(DMS)), &filters, None)?.0
                            .into_iter().map(|dm| dm.inner).collect::<Vec<DwnItem>>();
                        if results.is_empty() {
                            None
                        } else {
                            Some(serde_json::to_vec(&results)?)
                        }
                    } else {return auth_failed()}
                } else {
                    let payload = serde_json::from_slice::<ReadRequest>(&request.payload)?;
                    if let Ok((Verifier::Right(discover), _)) = payload.verify(&*self.did_resolver, None).await {
                        let results = self.database.get::<DwnItem>(None, &discover.to_vec())?;
                        results.map(|item| serde_json::to_vec(&item)).transpose()?
                    } else {return auth_failed();}
                };
                Ok(DwnResponse::new(200, "", results))
            },
            Action::Update => {
                let payload = serde_json::from_slice::<UpdateRequest>(&request.payload)?;
                if let Ok((Verifier::Right(key), item)) = payload.verify(&*self.did_resolver, None).await {
                    if let Some(old_item) = self.database.get::<DwnItem>(None, &item.discover.to_vec())? {
                        if old_item.delete != Some(key) {
                            return auth_failed();
                        }
                    }
                    self.database.set(None, &item)?;
                    return empty_success();
                }
                auth_failed()
            },
            Action::Delete => {
                let payload = serde_json::from_slice::<DeleteRequest>(&request.payload)?;
                if let Ok((Verifier::Right(delete), discover)) = payload.verify(&*self.did_resolver, None).await {
                    if let Some(old_item) = self.database.get::<DwnItem>(None, &discover.to_vec())? {
                        if old_item.delete == Some(delete) {
                            self.database.delete(None, &discover.to_vec())?;
                            return empty_success();
                        }
                    } else {return empty_success();}
                }
                auth_failed()
            }
        }
    }
}

impl std::fmt::Debug for DwnServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut fmt = f.debug_struct("DwnServer");
        fmt.field("did", &self.did.to_string())
        .field("key", &self.key.to_string())
        .field("location", &self.database.location())
        .field("items", &self.database.get_all::<DwnItem>(None).unwrap().into_iter().map(|item|
            (item.discover.to_string(), item.delete.map(|d| d.to_string()))
        ).collect::<Vec<(String, Option<String>)>>())
        .field("dm_item_count", &self.database.get_all::<DM>(Some(PathBuf::from(DMS))).unwrap().len())
        .finish()
    }
}
