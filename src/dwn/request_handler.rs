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
    Type
};
use super::traits::Router;
use super::json_rpc::JsonRpc;

use crate::dids::traits::DidResolver;
use crate::dids::structs::{DefaultDidResolver, Endpoint, Did};

use std::collections::BTreeSet;

#[derive(Debug, Clone)]
pub struct RequestHandler {
    pub did_resolver: Box<dyn DidResolver>,
    pub router: Box<dyn Router>,
}

impl RequestHandler {
    pub fn new(
        did_resolver: Box<dyn DidResolver>,
        router: Box<dyn Router>,
    ) -> Self {
        RequestHandler{did_resolver, router}
    }

    

    pub async fn handle(
        &self,
        request: &DwnRequest,
        dids: &[&Did]
    ) -> Result<Vec<DwnItem>, Error> {
        let responses = self.broadcast_request(request, dids).await?;
        match &request.action {
            Action::Create => {
                if request.r#type == Type::DM {
                    for res in responses {
                        res.handle(false)?;
                    }
                } else {
                    for res in responses {
                        if res.status.code != 409 {//Assume conflicts are the record already being created
                            res.handle(false)?;
                        }
                    }
                }
            },
            Action::Read => {
                if request.r#type == Type::DM {
                    return Ok(BTreeSet::from_iter(responses.into_iter().flat_map(|res| {
                            let data = res.handle(false).ok()??;
                            serde_json::from_slice::<Vec<DwnItem>>(&data).ok()
                        }).flatten()
                    ).into_iter().collect());
                } else {
                    return Ok(BTreeSet::from_iter(responses.into_iter().flat_map(|res| {
                        let data = res.handle(false).ok()??;
                        serde_json::from_slice::<DwnItem>(&data).ok()
                    })).into_iter().collect());
                }
            },
            Action::Update => {
                for res in responses {
                    res.handle(false)?;
                }
            },
            Action::Delete => {
                for res in responses {
                    res.handle(false)?;
                }
            }
        }
        Ok(vec![])
    }
}
