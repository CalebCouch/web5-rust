use super::Error;

use super::structs::{
    CreateDMRequest,
    ReadDMRequest,
    CreateRequest,
    UpdateRequest,
    DeleteRequest,
    ReadRequest,
    DwnResponse,
    DwnRequest,
    DwnItem,
    Packet,
    Action,
};
use super::traits::{
    Router,
    RequestHandler as RequestHandlerT
};
use super::json_rpc::JsonRpc;

use crate::dids::traits::DidResolver;
use crate::dids::structs::{Endpoint, Did};

use std::collections::BTreeSet;

#[derive(Debug, Clone)]
pub struct RequestHandler {
    pub router: Box<dyn Router>,
    pub did_resolver: Box<dyn DidResolver>,
}

impl RequestHandler {
    pub fn new(
        router: Option<Box<dyn Router>>,
        did_resolver: Box<dyn DidResolver>,
    ) -> Self {
        let router = router.unwrap_or(Box::new(JsonRpc::new()));
        RequestHandler{router, did_resolver}
    }
}

impl RequestHandler {
    async fn send_request(
        &self,
        endpoint: Endpoint,
        request: &DwnRequest
    ) -> Result<DwnResponse, Error> {
        let key = self.did_resolver.resolve_dwn_key(&endpoint.0).await?;
        let p = Packet{
            recipient: endpoint.0.clone(),
            payload: key.encrypt(&serde_json::to_vec(request)?)?
        };
        self.router.send_packet(p, endpoint.1).await
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
impl RequestHandlerT for RequestHandler {
    async fn create(
        &self,
        request: &CreateRequest,
        dids: &[&Did],
    ) -> Result<(), Error> {
        let request = DwnRequest::new(false, Action::Create, serde_json::to_vec(&request)?);
        let responses = self.broadcast_request(&request, dids).await?;
        for res in responses {
            if res.status.code != 409 {//Assume conflicts are the record already being created
                res.handle(false)?;
            }
        }
        Ok(())
    }

    async fn read(
        &mut self,
        rrequest: &ReadRequest,
        dids: &[&Did],
    ) -> Result<Vec<DwnItem>, Error> {
        let request = DwnRequest::new(false, Action::Read, serde_json::to_vec(&rrequest)?);
        let responses = self.broadcast_request(&request, dids).await?;
        Ok(BTreeSet::from_iter(responses.into_iter().flat_map(|res| {
            let data = res.handle(false).ok()??;
            serde_json::from_slice::<DwnItem>(&data).ok()
            .filter(|item| Some(&item.discover) == rrequest.signer().as_ref().right())
        })).into_iter().collect())
    }

    async fn update(
        &self,
        request: &UpdateRequest,
        dids: &[&Did],
    ) -> Result<(), Error> {
        let request = DwnRequest::new(false, Action::Update, serde_json::to_vec(&request)?);
        let responses = self.broadcast_request(&request, dids).await?;
        for res in responses {
            res.handle(false)?;
        }
        Ok(())
    }

    async fn delete(
        &self,
        request: &DeleteRequest,
        dids: &[&Did],
    ) -> Result<(), Error> {
        let request = DwnRequest::new(false, Action::Delete, serde_json::to_vec(&request)?);
        let responses = self.broadcast_request(&request, dids).await?;
        for res in responses {
            res.handle(false)?;
        }
        Ok(())
    }


    async fn create_dm(
        &self,
        request: &CreateDMRequest,
        recipient: &Did
    ) -> Result<(), Error> {
        let request = DwnRequest::new(true, Action::Create, serde_json::to_vec(&request)?);
        let responses = self.broadcast_request(&request, &[recipient]).await?;
        for res in responses {
            res.handle(false)?;
        }
        Ok(())
    }

    async fn read_dms(
        &self,
        request: &ReadDMRequest,
        recipient: &Did
    ) -> Result<Vec<DwnItem>, Error> {
        let request = DwnRequest::new(true, Action::Read, serde_json::to_vec(&request)?);
        Ok(BTreeSet::from_iter(
            self.broadcast_request(&request, &[recipient]).await?
            .into_iter().flat_map(|res| {
                let data = res.handle(false).ok()??;
                serde_json::from_slice::<Vec<DwnItem>>(&data).ok()
            }).flatten()
        ).into_iter().collect())
    }
}
