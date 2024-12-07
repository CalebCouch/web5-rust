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
use super::json_rpc::JsonRpcServer;
use super::traits;

use crate::dids::{DefaultDidResolver, DidResolver, Did};
use crate::dids::signing::Verifier;

use simple_crypto::SecretKey;
use simple_database::database::{FiltersBuilder, UuidKeyed, CmpType, Filter};
use simple_database::{KeyValueStore, Indexable, Database};

use std::path::PathBuf;

pub type DM = UuidKeyed<DwnItem>;

#[derive(Clone)]
pub struct Server {
    pub tenant: Did,
    pub com_key: SecretKey,
    pub private_database: Database,
    pub public_database: Database,
    pub dms_database: Database,
    pub server: Box<dyn traits::Server>,
    pub did_resolver: Box<dyn DidResolver>,
}

impl Server {
    pub async fn new<KVS: KeyValueStore + 'static>(
        tenant: Did,
        com_key: SecretKey,
        data_path: Option<PathBuf>,
        did_resolver: Option<Box<dyn DidResolver>>,
        server: Option<Box<dyn traits::Server>>,
    ) -> Result<Self, Error> {
        let data_path = data_path.unwrap_or(PathBuf::from("DWN"));
        let did_resolver = did_resolver.unwrap_or(Box::new(
            DefaultDidResolver::new::<KVS>(Some(data_path.join("DefaultDidResolver"))).await?
        ));
        let server = server.unwrap_or(Box::new(JsonRpcServer{}));
        Ok(Server{
            tenant,
            com_key,
            private_database: Database::new::<KVS>(data_path.join("DATABASE").join("PRIVATE")).await?,
            public_database: Database::new::<KVS>(data_path.join("DATABASE").join("PUBLIC")).await?,
            dms_database: Database::new::<KVS>(data_path.join("DATABASE").join("DMS")).await?,
            server,
            did_resolver,
        })
    }

    pub async fn start_server(self, port: u32) -> Result<actix_web::dev::Server, Error> {
        let server = self.server.clone();
        server.start_server(self, port).await
    }

    pub async fn process_packet(&mut self, packet: Packet) -> DwnResponse {
        if packet.recipient == self.tenant {
            let payload = match self.com_key.decrypt(&packet.payload) {
                Ok(res) => res,
                Err(e) => {return Into::<DwnResponse>::into(Into::<Error>::into(e));}
            };

            if let Ok(packet) = serde_json::from_slice::<Packet>(&payload) {
                Box::pin(async move {self.process_packet(packet).await}).await
            } else if let Ok(req) = serde_json::from_slice::<DwnRequest>(&payload) {
                match self.process_request(req).await {
                    Ok(res) => res,
                    Err(e) => Into::<DwnResponse>::into(e)
                }
            } else {
                Error::bad_request("dwn.process_packet", "Packet Could not be proccessed").into()
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
                        if self.private_database.get::<DwnItem>(&item.primary_key()).await?.is_some() {
                            return conflict();
                        }
                        self.private_database.set(&item).await?;
                        empty_success()
                    },
                    Action::Read => {
                        let payload = serde_json::from_slice::<PrivateReadRequest>(&request.payload)?;
                        if let Ok(Verifier::Right(discover)) = payload.verify(&*self.did_resolver, None).await {
                            let results = self.private_database.get::<DwnItem>(&discover.to_vec()).await?
                                .map(|item| serde_json::to_vec(&item)).transpose()?;
                            Ok(DwnResponse::new(200, "", results))
                        } else {auth_failed()}
                    },
                    Action::Update => {
                        let payload = serde_json::from_slice::<PrivateUpdateRequest>(&request.payload)?;
                        if let Ok(Verifier::Right(key)) = payload.verify(&*self.did_resolver, None).await {
                            let item = payload.unwrap();
                            if let Some(old_item) = self.private_database.get::<DwnItem>(&item.discover.to_vec()).await? {
                                if old_item.delete != Some(key) {
                                    return auth_failed();
                                }
                            }
                            self.private_database.set(&item).await?;
                            return empty_success();
                        }
                        auth_failed()
                    },
                    Action::Delete => {
                        let payload = serde_json::from_slice::<PrivateDeleteRequest>(&request.payload)?;
                        if let Ok(Verifier::Right(delete)) = payload.verify(&*self.did_resolver, None).await {
                            let discover = payload.unwrap();
                            if let Some(old_item) = self.private_database.get::<DwnItem>(&discover.to_vec()).await? {
                                if old_item.delete == Some(delete) {
                                    self.private_database.delete(&discover.to_vec()).await?;
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
                        if self.public_database.get::<PublicRecord>(&public_record.primary_key()).await?.is_some() {
                            return conflict();
                        }
                        self.public_database.set(&public_record).await?;
                        empty_success()
                    },
                    Action::Read => {
                        let (filters, sort_options) = serde_json::from_slice::<PublicReadRequest>(&request.payload)?;
                        let results = Some(self.public_database.query::<PublicRecord>(&filters, sort_options).await?.0)
                            .filter(|i| !i.is_empty())
                            .map(|i| serde_json::to_vec(&i)).transpose()?;
                        Ok(DwnResponse::new(200, "", results))
                    },
                    Action::Update => {
                        let public_record = serde_json::from_slice::<PublicUpdateRequest>(&request.payload)?;
                        let verifier = public_record.inner.verify(&*self.did_resolver, None).await?;
                        if let Some(old_record) = self.public_database.get::<PublicRecord>(&public_record.primary_key()).await? {
                            if old_record.inner.verify(&*self.did_resolver, Some(&verifier)).await.is_err() {
                                return auth_failed();
                            }
                        }
                        self.public_database.set(&public_record).await?;
                        empty_success()
                    }
                    Action::Delete => {
                        let payload = serde_json::from_slice::<PublicDeleteRequest>(&request.payload)?;
                        let verifier = payload.verify(&*self.did_resolver, None).await?;
                        let primary_key = payload.inner().as_bytes();
                        if let Some(old_record) = self.public_database.get::<PublicRecord>(primary_key).await? {
                            if old_record.inner.verify(&*self.did_resolver, Some(&verifier)).await.is_err() {
                                return auth_failed();
                            }
                            self.public_database.delete(primary_key).await?;
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
                        if self.dms_database.get::<DM>(&dm.primary_key()).await?.is_some() {
                            return conflict();
                        }
                        self.dms_database.set(&dm).await?;
                        empty_success()
                    },
                    Action::Read => {
                        let payload = serde_json::from_slice::<DMReadRequest>(&request.payload)?;
                        if let Ok(Verifier::Right(key)) = payload.verify(&*self.did_resolver, None).await {
                            let timestamp = payload.unwrap();
                            let filters = FiltersBuilder::build(vec![
                                ("timestamp_stored", Filter::cmp(CmpType::GT, timestamp)),
                                ("discover", Filter::equal(key.to_vec()))
                            ]);
                            let results = Some(self.dms_database.query::<DM>(&filters, None).await?.0
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

    pub async fn debug(&self) -> Result<String, Error> {
        Ok(
            self.tenant.to_string()+"\n"+
            &self.private_database.debug().await?+
            &self.public_database.debug().await?+
            &self.dms_database.debug().await?
        )
    }
}

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut fmt = f.debug_struct("Server");
        fmt.field("tenant", &self.tenant.to_string())
        .field("private_database", &self.private_database)
        .field("public_database", &self.public_database)
        .field("dms", &self.dms_database)
        .finish()
    }
}
