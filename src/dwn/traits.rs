use super::Error;

use crate::dids::Did;
use super::structs::DwnRequest;
use super::Server;
use dyn_clone::{clone_trait_object, DynClone};

#[async_trait::async_trait]
pub trait Router: DynClone + std::fmt::Debug + Sync + Send {
    async fn start_server(
        &self,
        dwn: Server,
        port: u32
    ) -> Result<actix_web::dev::Server, Error>;

    async fn handle_request(
        &self,
        request: &DwnRequest,
        dids: &[&Did]
    ) -> Result<Vec<Vec<u8>>, Error>;

}
clone_trait_object!(Router);
