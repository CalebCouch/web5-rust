use super::Error;

use super::traits::{Router, Client};
use super::structs::{Packet, DwnResponse, DwnRequest, Action, Type};
use crate::dids::{DidResolver, Endpoint, Did};

use super::json_rpc::JsonRpcClient;

use std::collections::BTreeSet;

#[derive(Debug, Clone)]
pub struct DefaultRouter {
    did_resolver: Box<dyn DidResolver>,
    client: Box<dyn Client>
}

impl DefaultRouter {
    pub fn new(
        did_resolver: Box<dyn DidResolver>,
        client: Option<Box<dyn Client>>
    ) -> Self {
        let client = client.unwrap_or(Box::new(JsonRpcClient{}));
        DefaultRouter{
            did_resolver,
            client
        }
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
        self.client.send_packet(p, endpoint.1).await
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
impl Router for DefaultRouter {
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
