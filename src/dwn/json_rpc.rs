use super::Error;

use super::traits::Router;
use super::structs::{Packet, DwnResponse, DwnRequest, Action, Type};
use super::Server;
use crate::dids::{DidResolver, Endpoint, Did};

use url::Url;
use tokio::sync::Mutex;
use jsonrpc_v2::{Data, Error as JsonError, Params, Server as JsonServer};

use std::collections::BTreeSet;

#[jsonrpc_client::api]
pub trait Methods {
    async fn process_packet(&self, recipient: Did, payload: Vec<u8>) -> DwnResponse;
    async fn debug(&self) -> String;
    async fn health(&self) -> String;
}

#[jsonrpc_client::implement(Methods)]
#[derive(Debug)]
struct Client {
    #[jsonrpc_client(inner)]
    my_client: reqwest::Client,
    #[jsonrpc_client(base_url)]
    url: Url,
}

#[derive(Debug, Clone)]
pub struct JsonRpc {
    did_resolver: Box<dyn DidResolver>
}

impl JsonRpc {
    pub fn new(
        did_resolver: Box<dyn DidResolver>
    ) -> Self {
        JsonRpc{did_resolver}
    }

    async fn process_packet(data: Data<Mutex<Server>>, Params(params): Params<Packet>) -> Result<DwnResponse, JsonError> {
        Ok(data.lock().await.process_packet(params).await?)
    }

    async fn send_packet(
        &self,
        p: Packet,
        url: Url
    ) -> Result<DwnResponse, Error> {
        log::info!("Sending packet to url: {}", url);
        let client = Client{
            my_client: reqwest::Client::new(),
            url
        };
        client.process_packet(p.recipient, p.payload).await.map_err(|e| Error::JsonRpc(e.to_string()))
    }

    async fn send_request(
        &self,
        endpoint: Endpoint,
        request: &DwnRequest
    ) -> Result<DwnResponse, Error> {
        log::info!("Sending request {:?} {:?} to did: {:?}", request.action, request.r#type, endpoint.0);
        let (_, key) = self.did_resolver.resolve_dwn_keys(&endpoint.0).await?;
        let p = Packet{
            recipient: endpoint.0.clone(),
            payload: key.encrypt(&serde_json::to_vec(request)?)?
        };
        self.send_packet(p, endpoint.1).await
    }

    async fn broadcast_request(
        &self,
        request: &DwnRequest,
        recipients: &[&Did]
    ) -> Result<Vec<DwnResponse>, Error> {
        let mut responses = Vec::new();
        let endpoints = self.did_resolver.get_endpoints(recipients).await?;
        for endpoint in endpoints.into_iter() {
            responses.push(self.send_request(endpoint, request).await?);
        }
        Ok(responses)
    }
}

#[async_trait::async_trait]
impl Router for JsonRpc {
    async fn start_server(&self, dwn: Server, port: u32) -> Result<actix_web::dev::Server, Error> {
        let rpc = JsonServer::new()
            .with_data(Data::new(Mutex::new(dwn)))
            .with_method("process_packet", Self::process_packet)
            .finish();
        let server = actix_web::HttpServer::new(move || {
            actix_web::App::new().service(
                actix_web::web::service("/")
                    .guard(actix_web::guard::Post())
                    .finish(rpc.clone().into_web_service()),
            )
        });
        Ok(server.bind(&format!("0.0.0.0:{}", port))?.run())
    }

    async fn handle_request(
        &self,
        request: &DwnRequest,
        dids: &[&Did]
    ) -> Result<Vec<Vec<u8>>, Error> {
        let responses = self.broadcast_request(request, dids).await?;
        match (&request.action, &request.r#type) {
            (Action::Create, Type::Private) => {
                for res in responses {
                    if res.status.code != 409 {//Assume conflicts are the record already being created
                        res.handle(false)?;
                    }
                }
            },
            (Action::Read, _) => {
                return Ok(BTreeSet::from_iter(responses.into_iter().flat_map(|res| {
                    res.handle(false).ok()?
                })).into_iter().collect::<Vec<Vec<u8>>>());
            },
            _ => {
                for res in responses {
                    res.handle(false)?;
                }
            },
        }
        Ok(vec![])
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
