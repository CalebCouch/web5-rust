use super::Error;

use super::structs::{
    PrivateCreateRequest,
    PrivateReadRequest,
    PrivateUpdateRequest,
    PrivateDeleteRequest,
    PublicCreateRequest,
    PublicUpdateRequest,
    PublicDeleteRequest,
    PublicReadRequest,
    DMCreateRequest,
    DMReadRequest,
    PublicRecord,
    DwnResponse,
    DwnRequest,
    DwnItem,
    Action,
    Packet,
    Type
};
use super::json_rpc::JsonRpc;
use super::traits::Router;

use crate::dids::structs::{DefaultDidResolver, Did};
use crate::dids::traits::DidResolver;
use crate::dids::signing::Verifier;

use simple_crypto::SecretKey;
use simple_database::database::{FiltersBuilder, UuidKeyed, CmpType, Filter};
use simple_database::{KeyValueStore, Indexable, Database};

use std::path::PathBuf;

pub type DM = UuidKeyed<DwnItem>;

pub struct Server {
    pub tenant: Did,
    pub com_key: SecretKey,
    pub private_database: Database,
    pub public_database: Database,
    pub dms_database: Database,
    pub router: Box<dyn Router>,
    pub did_resolver: Box<dyn DidResolver>,
}

impl Server {
    pub fn new<KVS: KeyValueStore + 'static>(
        tenant: Did,
        com_key: SecretKey,
        data_path: Option<PathBuf>,
        router: Option<Box<dyn Router>>,
        did_resolver: Option<Box<dyn DidResolver>>,
    ) -> Result<Self, Error> {
        let data_path = data_path.unwrap_or(PathBuf::from("DWN"));
        let did_resolver = did_resolver.unwrap_or(Box::new(DefaultDidResolver::new()));
        let router = router.unwrap_or(Box::new(JsonRpc::new(Some(did_resolver.clone()))));
        Ok(Server{
            tenant,
            com_key,
            private_database: Database::new::<KVS>(data_path.join("DATABASE").join("PRIVATE"))?,
            public_database: Database::new::<KVS>(data_path.join("DATABASE").join("PUBLIC"))?,
            dms_database: Database::new::<KVS>(data_path.join("DATABASE").join("DMS"))?,
            router,
            did_resolver,
        })
    }

    pub async fn start_server(self, port: u32) -> Result<(), Error> {
        let router = self.router.clone();
        router.start_server(self, port).await
    }

    pub async fn process_packet(&mut self, packet: Packet) -> Result<DwnResponse, Error> {
        if packet.recipient == self.tenant {
            let payload = self.com_key.decrypt(&packet.payload)?;
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

        match &request.r#type {
            Type::Private => {
                match &request.action {
                    Action::Create => {
                        let item = serde_json::from_slice::<PrivateCreateRequest>(&request.payload)?;
                        if self.private_database.get::<DwnItem>(&item.primary_key())?.is_some() {
                            return conflict();
                        }
                        self.private_database.set(&item)?;
                        empty_success()
                    },
                    Action::Read => {
                        let payload = serde_json::from_slice::<PrivateReadRequest>(&request.payload)?;
                        if let Ok(Verifier::Right(discover)) = payload.verify(&*self.did_resolver, None).await {
                            let results = self.private_database.get::<DwnItem>(&discover.to_vec())?
                                .map(|item| serde_json::to_vec(&item)).transpose()?;
                            Ok(DwnResponse::new(200, "", results))
                        } else {auth_failed()}
                    },
                    Action::Update => {
                        let payload = serde_json::from_slice::<PrivateUpdateRequest>(&request.payload)?;
                        if let Ok(Verifier::Right(key)) = payload.verify(&*self.did_resolver, None).await {
                            let item = payload.unwrap();
                            if let Some(old_item) = self.private_database.get::<DwnItem>(&item.discover.to_vec())? {
                                if old_item.delete != Some(key) {
                                    return auth_failed();
                                }
                            }
                            self.private_database.set(&item)?;
                            return empty_success();
                        }
                        auth_failed()
                    },
                    Action::Delete => {
                        let payload = serde_json::from_slice::<PrivateDeleteRequest>(&request.payload)?;
                        if let Ok(Verifier::Right(delete)) = payload.verify(&*self.did_resolver, None).await {
                            let discover = payload.unwrap();
                            if let Some(old_item) = self.private_database.get::<DwnItem>(&discover.to_vec())? {
                                if old_item.delete == Some(delete) {
                                    self.private_database.delete(&discover.to_vec())?;
                                    return empty_success();
                                }
                            } else {return empty_success();}
                        }
                        auth_failed()
                    }
                }
            },
            Type::Public => {
                match &request.action {
                    Action::Create => {
                        let public_record = serde_json::from_slice::<PublicCreateRequest>(&request.payload)?;
                        public_record.inner.verify(&*self.did_resolver, None).await?;
                        if self.public_database.get::<PublicRecord>(&public_record.primary_key())?.is_some() {
                            return conflict();
                        }
                        self.public_database.set(&public_record)?;
                        empty_success()
                    },
                    Action::Read => {
                        let (filters, sort_options) = serde_json::from_slice::<PublicReadRequest>(&request.payload)?;
                        let results = Some(self.public_database.query::<PublicRecord>(&filters, sort_options)?.0)
                            .filter(|i| !i.is_empty())
                            .map(|i| serde_json::to_vec(&i)).transpose()?;
                        Ok(DwnResponse::new(200, "", results))
                    },
                    Action::Update => {
                        let public_record = serde_json::from_slice::<PublicUpdateRequest>(&request.payload)?;
                        let verifier = public_record.inner.verify(&*self.did_resolver, None).await?;
                        if let Some(old_record) = self.public_database.get::<PublicRecord>(&public_record.primary_key())? {
                            if old_record.inner.verify(&*self.did_resolver, Some(&verifier)).await.is_err() {
                                return auth_failed();
                            }
                        }
                        self.public_database.set(&public_record)?;
                        empty_success()
                    }
                    Action::Delete => {
                        let payload = serde_json::from_slice::<PublicDeleteRequest>(&request.payload)?;
                        let verifier = payload.verify(&*self.did_resolver, None).await?;
                        let primary_key = payload.inner().as_bytes();
                        if let Some(old_record) = self.public_database.get::<PublicRecord>(primary_key)? {
                            if old_record.inner.verify(&*self.did_resolver, Some(&verifier)).await.is_err() {
                                return auth_failed();
                            }
                            self.public_database.delete(primary_key)?;
                        }
                        empty_success()


                    }
                }
            },
            Type::DM => {
                match &request.action {
                    Action::Create => {
                        let item = serde_json::from_slice::<DMCreateRequest>(&request.payload)?;
                        let dm = UuidKeyed::new(item);
                        if self.dms_database.get::<DM>(&dm.primary_key())?.is_some() {
                            return conflict();
                        }
                        self.dms_database.set(&dm)?;
                        empty_success()
                    },
                    Action::Read => {
                        let payload = serde_json::from_slice::<DMReadRequest>(&request.payload)?;
                        if let Ok(Verifier::Right(key)) = payload.verify(&*self.did_resolver, None).await {
                            let timestamp = payload.unwrap();
                            let filters = FiltersBuilder::build(vec![
                                ("timestamp_stored", Filter::cmp(CmpType::GT, timestamp.inner)),
                                ("discover", Filter::equal(key.to_vec()))
                            ]);
                            let results = Some(self.dms_database.query::<DM>(&filters, None)?.0
                                .into_iter().map(|dm| dm.inner()).collect::<Vec<DwnItem>>())
                                .filter(|i| !i.is_empty())
                                .map(|i| serde_json::to_vec(&i)).transpose()?;
                            Ok(DwnResponse::new(200, "", results))
                        } else {auth_failed()}
                    },
                    _ => Err(Error::err("DwnServer", "Unsupported method for DMs"))
                }
            }
        }
    }
}

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut fmt = f.debug_struct("Server");
        fmt.field("tenant", &self.tenant.to_string())
        .field("private_database", &self.private_database)
      //.field("private_items", &self.private_database.get_all::<DwnItem>().unwrap().into_iter().map(|item|
      //    (item.discover.to_string(), item.delete.map(|d| d.to_string()))
      //).collect::<Vec<(String, Option<String>)>>())
        .field("public_database", &self.public_database)
        .field("dms_count", &self.dms_database.get_all::<DM>().unwrap().len())
      //.field("public_record_count", &self.database.get_all::<PublicRecord>(Some(PathBuf::from(PUBLICS))).unwrap().len())
      //.field("public_items", &self.database.get_all::<PublicRecord>(Some(PathBuf::from(PUBLICS))).unwrap().into_iter().map(|pr| format!("{:?}", pr.inner.inner().1)).collect::<Vec<String>>())
        .finish()
    }
}
