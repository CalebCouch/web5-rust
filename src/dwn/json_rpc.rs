use super::Error;

use super::traits::{Server, Client};
use super::structs::{Packet, DwnResponse};
use crate::dids::Did;

use jsonrpc_v2::{Data, Error as JsonError, Params, Server as JsonServer};
use tokio::sync::Mutex;
use url::Url;

#[jsonrpc_client::api]
pub trait Method {
    async fn process_packet(&self, recipient: Did, payload: Vec<u8>) -> DwnResponse;
    async fn debug(&self) -> String;
}

#[jsonrpc_client::implement(Method)]
#[derive(Debug)]
struct JsonClient {
    inner: reqwest::Client,
    base_url: Url,
}

#[derive(Debug, Clone)]
pub struct JsonRpcClient {}

impl JsonRpcClient {
    pub async fn client_debug(url: &str) -> String {
        let client = JsonClient{inner: reqwest::Client::new(), base_url: Url::parse(url).unwrap()};
        client.debug().await.unwrap()
    }
}

#[async_trait::async_trait]
impl Client for JsonRpcClient {
    async fn send_packet(
        &self,
        p: Packet,
        url: Url
    ) -> Result<DwnResponse, Error> {
        let client = JsonClient{inner: reqwest::Client::new(), base_url: url};
        client.process_packet(p.recipient, p.payload).await.map_err(|e|
            Error::JsonRpc(e.to_string()
        ))
    }
}

#[derive(Debug, Clone)]
pub struct JsonRpcServer {}

impl JsonRpcServer {
    async fn process_packet(
        data: Data<Mutex<super::Server>>, Params(params): Params<Packet>
    ) -> Result<DwnResponse, JsonError> {
        Ok(data.lock().await.process_packet(params).await)
    }

    async fn debug(data: Data<Mutex<super::Server>>) -> Result<String, JsonError> {
        Ok(data.lock().await.debug().await.unwrap())
    }
}

#[async_trait::async_trait]
impl Server for JsonRpcServer {
    async fn start_server(
        &self, dwn: super::Server, port: u32
    ) -> Result<actix_web::dev::Server, Error> {
        let rpc = JsonServer::new()
            .with_data(Data::new(Mutex::new(dwn)))
            .with_method("process_packet", Self::process_packet)
            .with_method("debug", Self::debug)
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
}
