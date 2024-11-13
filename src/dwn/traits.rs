use super::Error;

use dyn_clone::{clone_trait_object, DynClone};

#[async_trait::async_trait]
pub trait Client: DynClone + std::fmt::Debug + Sync + Send {
    async fn send_request(
        &self,
        body: String,
        url: url::Url
    ) -> Result<String, Error>;
}
clone_trait_object!(Client);

#[async_trait::async_trait]
pub trait Server: DynClone + std::fmt::Debug + Sync + Send {
    async fn start_server(
        &self,
        dwn: super::Dwn,
        port: u32
    ) -> Result<actix_web::dev::Server, Error>;

}
clone_trait_object!(Server);
