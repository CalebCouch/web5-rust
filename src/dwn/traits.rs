use super::Error;

use crate::dids::Did;
use super::structs::{DwnResponse, DwnRequest, Packet};
use dyn_clone::{clone_trait_object, DynClone};

#[async_trait::async_trait]
pub trait Client: DynClone + std::fmt::Debug + Sync + Send {
    async fn send_packet(
        &self,
        p: Packet,
        url: url::Url
    ) -> Result<DwnResponse, Error>;
}
clone_trait_object!(Client);

#[async_trait::async_trait]
pub trait Router: DynClone + std::fmt::Debug + Sync + Send {
    async fn handle_request(
        &self,
        request: &DwnRequest,
        dids: &[&Did]
    ) -> Result<Vec<Vec<u8>>, Error>;

}
clone_trait_object!(Router);

#[async_trait::async_trait]
pub trait Server: DynClone + std::fmt::Debug + Sync + Send {
    async fn start_server(
        &self,
        dwn: super::Server,
        port: u32
    ) -> Result<actix_web::dev::Server, Error>;

}
clone_trait_object!(Server);
