use super::Error;

use super::structs::{
    PermissionedRecord,
    CreateDMRequest,
    RequestBuilder,
    ReadDMRequest,
    DwnItem,
    Record,
};
use super::permission::Permission;
use super::protocol::Protocol;
use super::RequestHandler;
use super::traits::{RequestHandler as RequestHandlerT, Client, P2P};

use crate::common::structs::{DateTime, Either};
use crate::common::traits::KeyValueStore;

use crate::crypto::structs::Hash;
use crate::crypto::traits::Hashable;
use crate::crypto::secp256k1::{PublicKey, SecretKey};

use crate::dids::signing::SignedObject;
use crate::dids::traits::DidResolver;
use crate::dids::structs::{DidKeyPair, Did};

use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct DwnClient {
    pub tenant: Did,
    pub request_handler: Box<dyn RequestHandlerT>,
    pub protocols: Box<dyn KeyValueStore>,
    pub did_resolver: Box<dyn DidResolver>,
    pub p2p: Box<dyn P2P>
}

impl DwnClient {
    pub fn new<KVS: KeyValueStore + 'static>(
        tenant: Did,
        request_handler: Option<Box<dyn RequestHandlerT>>,
        protocols: Option<Box<dyn KeyValueStore>>,
        did_resolver: Box<dyn DidResolver>,
        p2p: Box<dyn P2P>
    ) -> Result<Self, Error> {
        let request_handler = request_handler.unwrap_or(Box::new(RequestHandler::new(None, did_resolver.clone())));
        let protocols = protocols.unwrap_or(Box::new(KVS::new(PathBuf::from("PROTOCOLS"))?));
        Ok(DwnClient{tenant, request_handler, protocols, did_resolver, p2p})
    }

    async fn get_next_channel_index(
        &mut self,
        discover_child: &SecretKey,
        start: usize,
        dids: &[&Did]
    ) -> Result<usize, Error> {
        let mut index = start;
        loop {
            let discover = discover_child.derive_usize(index)?;
            let request = RequestBuilder::read(&discover)?;
            if self.request_handler.read(&request, dids).await?.is_empty() {
                for i in 0..11 {
                    let discover = discover_child.derive_usize(index)?;
                    let request = RequestBuilder::read(&discover)?;
                    if !self.request_handler.read(&request, dids).await?.is_empty() {
                        index += i;
                        break;
                    }
                    if i == 10 {return Ok(index);}
                }
            }
            index += 1;
        }
    }
}

#[async_trait::async_trait]
impl Client for DwnClient {
    async fn create(
        &mut self,
        perms: &Permission,
        record: Record,
        dids: &[&Did],
    ) -> Result<Permission, Error> {
        let error = |r: &str| Error::bad_request("DwnClient.create", r);
        let protocol = self.get_protocol(&record.protocol).await?;
        let trimmed_perms = protocol.trim_perms(perms)?;
        let perm_record = (trimmed_perms.clone(), record);
        protocol.validate(&perm_record)?;
        let create = perms.create.as_ref().right().ok_or(error("Create Permission Missing"))?;
        let request = RequestBuilder::create(create, perm_record)?;
        self.request_handler.create(&request, dids).await?;
        Ok(trimmed_perms)
    }

    async fn read(
        &mut self,
        perms: &Permission,
        dids: &[&Did],
        follow_perm: bool
    ) -> Result<Option<PermissionedRecord>, Error> {
        let error = |r: &str| Error::bad_request("DwnClient.read", r);
        let create = perms.create.map_ref_to_left(|k| k.public_key());
        let read = perms.read.clone().right().ok_or(error("Read Permission Missing"))?;
        let request = RequestBuilder::read(&perms.discover)?;
        let items = self.request_handler.read(&request, dids).await?;
        let prds: Vec<(PermissionedRecord, Option<PublicKey>)> = items.into_iter().flat_map(|item| {
            let dc = read.decrypt(&item.payload).ok()?;
            let signed = serde_json::from_slice::<SignedObject<PermissionedRecord>>(&dc).ok()?;
            Some((signed.verify_with_key(&create).ok()?, item.delete))
        }).collect();
        for (pr, d) in prds {
            if let Ok(protocol) = self.get_protocol(&pr.1.protocol).await {
                if let Ok(trimmed_perms) = protocol.trim_perms(perms) {
                    if d != trimmed_perms.delete.as_ref().map(|d| d.map_ref_to_left(|k| k.public_key())) {continue;}
                    if protocol.validate(&pr).is_err() {continue;}
                    if follow_perm && protocol == Protocol::permission_grant() {
                        let permission = serde_json::from_slice::<Permission>(&pr.1.payload)?;
                        return Box::pin(self.read(&permission, dids, false)).await
                    } else {
                        return Ok(Some((pr.0.combine(perms.clone())?, pr.1)));
                    }
                }
            }
        }
        Ok(None)
    }

    async fn update(
        &mut self,
        perms: &Permission,
        record: Record,
        dids: &[&Did],
    ) -> Result<Permission, Error> {
        let error = |r: &str| Error::bad_request("DwnClient.update", r);
        let protocol = self.get_protocol(&record.protocol).await?;
        let trimmed_perms = protocol.trim_perms(perms)?;
        let perm_record = (trimmed_perms.clone(), record);
        protocol.validate(&perm_record)?;
        let create = perms.create.as_ref().right().ok_or(error("Create Permission Missing"))?;
        let d_error = || error("Delete Permission Missing");
        let delete = perms.delete.clone().ok_or(d_error())?.right().ok_or(d_error())?;
        let request = RequestBuilder::update(create, &delete, perm_record)?;
        self.request_handler.update(&request, dids).await?;
        Ok(trimmed_perms)
    }

    async fn delete(
        &mut self,
        perms: &Permission,
        dids: &[&Did]
    ) -> Result<(), Error> {
        let error = || Error::bad_request("DwnClient.delete", "Delete Permission Missing");
        let delete = perms.delete.as_ref().ok_or(error())?.as_ref().right().ok_or(error())?;
        let request = RequestBuilder::delete(delete, perms.discover.public_key())?;
        self.request_handler.delete(&request, dids).await
    }

    async fn create_child(
        &mut self,
        perms: &Permission,
        latest_delete: usize,
        permission: Permission,
        dids: &[&Did]
    ) -> Result<(Permission, usize), Error> {
        let error = |r: &str| Error::bad_request("DwnClient.create_child", r);
        let channel = perms.channel.as_ref().ok_or(error("Missing Channel Perms"))?;
        let discover_child = channel.discover.as_ref().right().ok_or(error("Missing DiscoverChild Perms"))?;
        let index = self.get_next_channel_index(discover_child, latest_delete, dids).await?;
        let discover = discover_child.derive_usize(index)?;
        let create = channel.create.clone().right().ok_or(error("Missing CreateChild Perms"))?;
        let read = channel.read.map_ref_to_left(|k| k.public_key());
        let child_perms = Permission::new(
            discover, Either::Right(create), Either::Left(read), None, None
        );
        let record = Record::new(None, Protocol::channel_item().hash(), serde_json::to_vec(&permission)?);
        Ok((self.create(&child_perms, record, dids).await?, index))
    }

    async fn read_child(
        &mut self,
        perms: &Permission,
        start: usize,
        end: Option<usize>,
        dids: &[&Did]
    ) -> Result<Vec<PermissionedRecord>, Error> {
        let error = |r: &str| Error::bad_request("DwnClient.read_child", r);
        let (perms, parent) = self.read(perms, dids, true).await?.ok_or(error("Could not get parent"))?;
        let deletes = &parent.channel_deletes;
        let protocol = self.get_protocol(&parent.protocol).await?;
        let channel = perms.channel.as_ref().ok_or(error("Channel Permissions Missing"))?;
        let discover_child = channel.discover.as_ref().right().ok_or(error("DiscoverChild Permissions Missing"))?;
        let read = Either::Right(channel.read.clone().right().ok_or(error("DiscoverChild Permissions Missing"))?);
        let create = Either::Left(channel.create.map_ref_to_left(|k| k.public_key()));

        let mut results: Vec<PermissionedRecord> = Vec::new();
        let mut index = start;
        let mut child_perms = Permission::new(discover_child.derive_usize(index)?, create.clone(), read.clone(), None, None);
        let mut empties = 0;
        loop {
            if let Some(end) = end {if index >= end {break;}}
            if empties >= 10 {break;}
            if deletes.contains(&index) {index += 1; continue;}
            child_perms.discover = discover_child.derive_usize(index)?;
            if let Some(perm_record) = self.read(&child_perms, dids, true).await? {
                if protocol.validate_child(&perm_record).is_ok() {
                    results.push(perm_record);
                }
                empties = 0;
            } else {
                empties += 1;
            }
            index += 1;
        }
        Ok(results)
    }

    async fn delete_child(
        &mut self,
        perms: &Permission,
        index: usize,
        dids: &[&Did]
    ) -> Result<(), Error> {
        let error = |r: &str| Error::bad_request("DwnClient.delete_child", r);
        let mut parent = self.read(perms, dids, true).await?.ok_or(error("Could not find record"))?;
        parent.1.channel_deletes.push(index);
        self.update(&parent.0, parent.1, dids).await?;
        Ok(())
    }

    async fn configure_protocol(&mut self, protocol: Protocol) -> Result<(), Error> {
        let record = Record::new(None, Protocol::configure_protocol().hash(), serde_json::to_vec(&protocol)?);
        let perms = self.p2p.p_to_p(&protocol.hash())?;
        self.create(&perms, record, &[&self.tenant.clone()]).await?;
        self.protocols.set(protocol.hash().as_bytes(), &serde_json::to_vec(&protocol)?)?;
        Ok(())
    }

    async fn get_protocol(&mut self, protocol: &Hash) -> Result<Protocol, Error> {
        if let Some(protocol) = Protocol::system_protocols().remove(protocol) {
            Ok(protocol)
        } else if let Some(protocol) = self.protocols.get(protocol.as_bytes())? {
            let protocol = serde_json::from_slice::<Protocol>(&protocol)?;
            Ok(protocol)
        } else {
            let perms = self.p2p.p_to_p(protocol)?;
            if let Some((_, record)) = Box::pin(self.read(&perms, &[&self.tenant.clone()], false)).await? {
                let protocol: Protocol = serde_json::from_slice(&record.payload)?;
                self.protocols.set(protocol.hash().as_bytes(), &serde_json::to_vec(&protocol)?)?;
                Ok(protocol)
            } else {
                Err(Error::not_found("Agent.get_protocol", "Protocol could not be found"))
            }
        }
    }

    async fn create_did_msg(
        &self,
        sender: &DidKeyPair,
        recipient: &Did,
        permission: Permission,
    ) -> Result<(), Error> {
        let key = self.did_resolver.resolve_dwn_key(recipient).await?;
        let signed = SignedObject::from_keypair(sender, permission)?;
        let payload = key.encrypt(&serde_json::to_vec(&signed)?)?;
        let request: CreateDMRequest = DwnItem::new(key, None, payload);
        self.request_handler.create_dm(&request, recipient).await
    }

    async fn read_did_msgs(
        &self,
        recipient: (&Did, &SecretKey),
        timestamp: DateTime
    ) -> Result<Vec<(Did, Permission)>, Error> {
        let request: ReadDMRequest = SignedObject::from_key(recipient.1, timestamp)?;
        let items = self.request_handler.read_dms(&request, recipient.0).await?;
        let mut results: Vec<(Did, Permission)> = Vec::new();
        for item in items {
            if item.discover != recipient.1.public_key() || item.delete.is_some() {continue;}
            if let Ok(dc) = recipient.1.decrypt(&item.payload) {
                if let Ok(signed) = serde_json::from_slice::<SignedObject<Permission>>(&dc) {
                    if let Ok((Either::Left(sender), perm)) = signed.verify(&*self.did_resolver, None).await {
                        results.push((sender, perm));
                    }
                }
            }
        }
        Ok(results)
    }
}

