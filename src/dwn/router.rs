use super::Error;

use super::traits::Client;
use super::structs::{DwnResponse, DwnRequest, Packet};

use crate::dids::{DidResolver, Endpoint};

use std::collections::BTreeMap;

use futures::future;
use uuid::Uuid;
use url::Url;

use crate::agent::traits::TypeDebug;

pub struct Router<'a> {
    did_resolver: &'a dyn DidResolver,
    client: Box<dyn Client>
}

impl<'a> Router<'a> {
    pub fn new(
        did_resolver: &'a dyn DidResolver,
        client: Box<dyn Client>,
    ) -> Self {
        Router{did_resolver, client}
    }

    async fn send_packet(
        &self,
        packet: &Packet,
        url: Url,
    ) -> Result<BTreeMap<Uuid, DwnResponse>, Error> {
        let response = self.client.send_request(serde_json::to_string(packet)?, url).await?;
        Ok(serde_json::from_str(&response)?)
    }

    pub async fn send(
        &self,
        requests: BTreeMap<Endpoint, BTreeMap<Uuid, Box<DwnRequest>>>,
    ) -> Result<BTreeMap<Endpoint, BTreeMap<Uuid, DwnResponse>>, Error> {
        Ok(BTreeMap::from_iter(future::try_join_all(requests.into_iter().map(|(ep, request)| async move {
            println!("EPREQUEST BATCH: {:?}, {:#?}", ep.1.to_string(), request.iter().map(|(h, v)| format!("{:?}", (h, v.truncate_debug()))).collect::<Vec<_>>());
            let ser_reqs = serde_json::to_vec(&request)?;
            Ok::<_, Error>((ep.clone(), self.send_packet(&Packet::new(self.did_resolver, ep.0, &ser_reqs).await?, ep.1).await?))
        })).await?))
    }
}
