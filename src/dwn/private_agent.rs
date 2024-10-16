use super::Error;
use simple_crypto::{SecretKey, Hash};
use super::structs::ProtocolFetcher;
use simple_database::database::{SortOptions, Filters, Index};
use super::permission::PermissionSet;

use super::json_rpc::JsonRpc;
use crate::dids::structs::{
    DefaultDidResolver,
    DidKeyPair,
    Did,
};
use crate::dids::traits::DidResolver;
use crate::dids::signing::Verifier;
use super::structs::{Record, DwnKey};
use super::permission::PermissionOptions;
use super::protocol::Protocol;
use super::traits::Router;
use super::{PrivateClient, PublicClient, DMClient};

use std::collections::BTreeMap;

use either::Either;

#[derive(Debug)]
pub struct PrivateAgent {
    key: DwnKey,
    private_client: &'static PrivateClient,
}

impl PrivateAgent {
    pub fn new(
        key: DwnKey,
        private_client: &'static PrivateClient,
    ) -> Self {
        PrivateAgent{
            key,
            private_client,
        }
    }

    pub async fn create(
        &mut self,
        parent_path: &[Hash],
        permission_options: Option<&PermissionOptions>,
        record: Record,
        dids: &[&Did],
    ) -> Result<Vec<Hash>, Error> {
        let error = |r: &str| Error::bad_request("Agent.create", r);
        let record_path = [parent_path.to_vec(), vec![record.record_id]].concat();
        let record_perms = self.get_permission(&record_path)?;
        let child_protocol = record.protocol;
        let perm_parent = self.private_client.read(&self.get_permission(parent_path)?, dids).await?.ok_or(error("Parent could not be found"))?;
        let perms = self.private_client.create(record_perms, permission_options, record, dids).await?;
        self.private_client.create_child(&perm_parent, &child_protocol, &perms, dids).await?;
        Ok(record_path)
    }

    pub async fn read(
        &mut self,
        path: &[Hash],
        index: Option<usize>,
        dids: &[&Did]
    ) -> Result<Option<Record>, Error> {
        let perms = self.get_permission(path)?;
        if let Some(record) = if path.is_empty() {Some(self.private_client.init_root(perms.clone(), dids).await?)} else {self.private_client.read(&perms, dids).await?} {
            if let Some(index) = index {
                Ok(self.private_client.read_child(&record, Some(index), Some(index), dids).await?.0.first().map(|pr| pr.0.1.clone()))
            } else {
                Ok(Some(record.1))
            }
        } else {
            Ok(None)
        }
    }

    pub async fn update(
        &mut self,
        path: &[Hash],
        permission_options: Option<&PermissionOptions>,
        record: Record,
        dids: &[&Did],
    ) -> Result<(), Error> {
        let perms = self.get_permission(path)?;
        self.private_client.update(perms, permission_options, record, dids).await?;
        Ok(())
    }

    pub async fn delete(
        &mut self,
        path: &[Hash],
        dids: &[&Did],
    ) -> Result<bool, Error> {
        if let Some(record) = self.private_client.read(&self.get_permission(path)?, dids).await? {
            self.private_client.delete(&record.0, dids).await?;
            Ok(true)
        } else {Ok(false)}
    }

    fn get_permission(&self, path: &[Hash]) -> Result<PermissionSet, Error> {
        PermissionSet::from_key(&self.key.from_path(path)?)
    }
}
