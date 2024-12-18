use super::Error;

use super::traits::Client;
use super::structs::{DwnResponse, DwnRequest, Packet};

use crate::dids::{DidResolver, Endpoint};

use std::collections::BTreeMap;

use futures::future;
use uuid::Uuid;
use url::Url;

#[derive(Clone)]
pub struct Router {
    did_resolver: Box<dyn DidResolver>,
    client: Box<dyn Client>
}

impl Router {
    pub fn new(
        did_resolver: Box<dyn DidResolver>,
        client: Box<dyn Client>,
    ) -> Self {
        Router{did_resolver, client}
    }

    async fn send_packet(
        &self,
        packet: &Packet,
        url: Url,
    ) -> Result<Vec<(Uuid, DwnResponse)>, Error> {
        let response = self.client.send_request(serde_json::to_string(packet)?, url).await?;
        Ok(serde_json::from_str(&response)?)
    }

    pub async fn send(
        &self,
        requests: BTreeMap<Endpoint, Vec<(Uuid, Box<DwnRequest>)>>,
    ) -> Result<BTreeMap<Endpoint, BTreeMap<Uuid, DwnResponse>>, Error> {
        Ok(BTreeMap::from_iter(future::try_join_all(requests.into_iter().map(|(ep, request)| async move {
            let ser_reqs = serde_json::to_vec(&request)?;
            Ok::<_, Error>((ep.clone(), BTreeMap::from_iter(self.send_packet(&Packet::new(&*self.did_resolver, ep.0, &ser_reqs).await?, ep.1).await?)))
        })).await?))
    }
}
