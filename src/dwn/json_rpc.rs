use super::Error;

use super::traits::Router;
use super::structs::{Packet, DwnResponse};

use crate::common::structs::Url;

use crate::dids::structs::Did;

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
    url: reqwest::Url,
}

#[derive(Debug, Clone, Default)]
pub struct JsonRpc {}

impl JsonRpc {
    pub fn new() -> Self {JsonRpc{}}
    pub async fn debug(&self, url: &str) -> Result<String, Error> {
        Client{
            my_client: reqwest::Client::new(),
            url: reqwest::Url::parse(url)?
        }.debug().await.map_err(|e| Error::JsonRpc(e.to_string()))
    }
    pub async fn health(&self, url: &str) -> Result<String, Error> {
        Client{
            my_client: reqwest::Client::new(),
            url: reqwest::Url::parse(url)?
        }.health().await.map_err(|e| Error::JsonRpc(e.to_string()))
    }
}

#[async_trait::async_trait]
impl Router for JsonRpc {
    async fn send_packet(
        &self,
        p: Packet,
        url: Url
    ) -> Result<DwnResponse, Error> {
        let client = Client{
            my_client: reqwest::Client::new(),
            url: reqwest::Url::parse(&url.to_string())?
        };
        Ok(match client.process_packet(p.recipient, p.payload).await {
            Ok(res) => res,
            Err(e) => Error::JsonRpc(e.to_string()).into()
        })
    }
}
