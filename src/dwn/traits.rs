use super::Error;
use crate::common::structs::{DateTime, Url};
use crate::crypto::secp256k1::SecretKey;
use crate::crypto::structs::Hash;
use crate::dids::structs::{DidKeyPair, Did};
use super::structs::{
    CreateDMRequest,
    ReadDMRequest,
    CreateRequest,
    UpdateRequest,
    DeleteRequest,
    ReadRequest,
    DwnResponse,
    DwnItem,
    Record,
    Packet,
};
use super::permission::Permission;
use super::protocol::Protocol;
use dyn_clone::{clone_trait_object, DynClone};

pub trait P2P: DynClone + Sync + Send + std::fmt::Debug {
    fn p_to_p(&self, protocol: &Hash) -> Result<Permission, Error>;
}
clone_trait_object!(P2P);

#[async_trait::async_trait]
pub trait Router: DynClone + std::fmt::Debug + Sync + Send {
    async fn send_packet(
        &self,
        packet: Packet,
        url: Url
    ) -> Result<DwnResponse, Error>;
}
clone_trait_object!(Router);

#[async_trait::async_trait]
pub trait RequestHandler: DynClone + std::fmt::Debug + Sync + Send {
    async fn create(
        &self,
        request: &CreateRequest,
        dids: &[&Did],
    ) -> Result<(), Error>;

    async fn read(
        &mut self,
        request: &ReadRequest,
        dids: &[&Did],
    ) -> Result<Vec<DwnItem>, Error>;

    async fn delete(
        &self,
        request: &DeleteRequest,
        dids: &[&Did],
    ) -> Result<(), Error>;

    async fn update(
        &self,
        request: &UpdateRequest,
        dids: &[&Did],
    ) -> Result<(), Error>;

    async fn create_dm(
        &self,
        request: &CreateDMRequest,
        recipient: &Did
    ) -> Result<(), Error>;

    async fn read_dms(
        &self,
        request: &ReadDMRequest,
        recipient: &Did
    ) -> Result<Vec<DwnItem>, Error>;
}
clone_trait_object!(RequestHandler);

#[async_trait::async_trait]
pub trait Client: DynClone + std::fmt::Debug + Sync + Send {
    async fn create(
        &mut self,
        perms: &Permission,
        record: Record,
        dids: &[&Did]
    ) -> Result<Permission, Error>;

    async fn read(
        &mut self,
        perms: &Permission,
        dids: &[&Did],
        follow_perm: bool
    ) -> Result<Option<(Permission, Record)>, Error>;

    async fn update(
        &mut self,
        perms: &Permission,
        record: Record,
        dids: &[&Did]
    ) -> Result<Permission, Error>;

    async fn delete(
        &mut self,
        perms: &Permission,
        dids: &[&Did]
    ) -> Result<(), Error>;

    async fn create_child(
        &mut self,
        perms: &Permission,
        latest_delete: usize,
        permission: Permission,
        dids: &[&Did]
    ) -> Result<(Permission, usize), Error>;

    async fn read_child(
        &mut self,
        perms: &Permission,
        start: usize,
        end: Option<usize>,
        dids: &[&Did]
    ) -> Result<Vec<(Permission, Record)>, Error>;

    async fn delete_child(
        &mut self,
        perms: &Permission,
        index: usize,
        dids: &[&Did]
    ) -> Result<(), Error>;

    async fn configure_protocol(&mut self, protocol: Protocol) -> Result<(), Error>;
    async fn get_protocol(&mut self, protocol: &Hash) -> Result<Protocol, Error>;

    async fn create_did_msg(
        &self,
        sender: &DidKeyPair,
        recipient: &Did,
        permission: Permission,
    ) -> Result<(), Error>;

    async fn read_did_msgs(
        &self,
        recipient: (&Did, &SecretKey),
        timestamp: DateTime
    ) -> Result<Vec<(Did, Permission)>, Error>;
}
clone_trait_object!(Client);
