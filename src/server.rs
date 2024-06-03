use super::Error;

use crate::common::traits::{KeyValueStore};

use crate::crypto::secp256k1::SecretKey;

use crate::dids::traits::DidResolver;
use crate::dids::structs::Did;

use crate::dwn::structs::{DwnResponse, Packet};
use crate::dwn::DwnServer;

use std::path::PathBuf;
use tokio::sync::Mutex;

use jsonrpc_v2::{Data, Error as JsonError, Params, Server as JsonServer};

#[derive(Debug)]
pub struct Server {
    pub dwn: DwnServer,
}

impl Server {
    pub fn new<KVS: KeyValueStore + 'static>(
        data_path: Option<PathBuf>,
        did: Did,
        key: SecretKey,
        did_resolver: Option<Box<dyn DidResolver>>,
    ) -> Result<Server, Error> {
        let data_path = data_path.unwrap_or(PathBuf::from("SERVER_DWN"));
        Ok(Server{
            dwn: DwnServer::new::<KVS>(Some(data_path), did, key, did_resolver)?
        })
    }

    async fn health() -> Result<String, Error> {
        Ok(String::from("200: OK"))
    }

    //TODO: REMOVE
    async fn debug(data: Data<Mutex<DwnServer>>) -> Result<String, Error> {
        Ok(format!("{:#?}", data.lock().await))
    }

    async fn process_packet(data: Data<Mutex<DwnServer>>, Params(params): Params<Packet>) -> Result<DwnResponse, JsonError> {
        Ok(data.lock().await.process_packet(params).await?)
    }

    pub fn get_server(self, port: u32) -> Result<actix_web::dev::Server, Error> {
        let rpc = JsonServer::new()
        .with_data(Data::new(Mutex::new(self.dwn)))
        .with_method("process_packet", Server::process_packet)
        .with_method("health", Server::health)
        .with_method("debug", Server::debug)
        .finish();
        Ok(actix_web::HttpServer::new(move || {
            actix_web::App::new().service(
                actix_web::web::service("/")
                    .guard(actix_web::guard::Post())
                    .finish(rpc.clone().into_web_service()),
            )
        })
        .bind(&format!("0.0.0.0:{}", port))?
        .run())
    }
}

impl From<Error> for JsonError {
    fn from(item: Error) -> Self {
        match item {
            Error::BadRequest(ctx, err) => JsonError::Full{code: 400, message: Error::BadRequest(ctx, err).to_string(), data: None},
            Error::AuthFailed(ctx, err) => JsonError::Full{code: 401, message: Error::AuthFailed(ctx, err).to_string(), data: None},
            Error::NotFound(ctx, err) => JsonError::Full{code: 404, message: Error::NotFound(ctx, err).to_string(), data: None},
            Error::Conflict(ctx, err) => JsonError::Full{code: 409, message: Error::Conflict(ctx, err).to_string(), data: None},
            other => JsonError::Full{code: 500, message: other.to_string(), data: None}
        }
    }
}
