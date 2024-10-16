use super::Error;

use super::json_rpc::JsonRpc;
use simple_database::database::{Index, SortOptions, Filters};

use super::structs::{
    PermissionedRecord,
    PrivateCreateRequest,
    PrivateReadRequest,
    PrivateUpdateRequest,
    PrivateDeleteRequest,
    PublicCreateRequest,
    PublicUpdateRequest,
    PublicDeleteRequest,
    PublicReadRequest,
    DMCreateRequest,
    DMReadRequest,
    DwnResponse,
    DwnRequest,
    PublicRecord,
    DwnItem,
    Packet,
    Record,
    Action,
    Type
};

use super::permission::{PermissionSet, PermissionOptions};
use super::protocol::Protocol;
use super::traits::Router;

use crate::common::DateTime;

use simple_crypto::{SecretKey, PublicKey, Key, Hashable, Hash};

use crate::dids::signing::{SignedObject, Signer, Verifier};
use crate::dids::traits::DidResolver;
use crate::dids::structs::{DefaultDidResolver, DidKeyPair, Endpoint, Did};

use simple_database::KeyValueStore;

use either::Either;

use std::path::PathBuf;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone)]
pub struct Client {
    router: Box<dyn Router>,
    did_resolver: Box<dyn DidResolver>,
    protocols: BTreeMap<Hash, Protocol>,
    sys_protocols: BTreeMap<Hash, Protocol>,
}

impl Client {
    pub fn new(
        router: Box<dyn Router>,
        did_resolver: Box<dyn DidResolver>,
        protocols: BTreeMap<Hash, Protocol>,
    ) -> Self {
        Client{router, did_resolver, protocols, sys_protocols: Protocol::system_protocols()}
    }

    pub async fn private_create(
        &self,
        perms: PermissionSet,
        permission_options: &PermissionOptions,
        record: Record,
        dids: &[&Did],
    ) -> Result<PermissionSet, Error> {
        let create = perms.create.secret_key().ok_or(Error::bad_request("Client.create", "Create Permission Missing"))?;

        let (trimmed_perms, perm_record) = self.construct_perm_record(perms, permission_options, record)?;
        let payload: PrivateCreateRequest = Self::construct_dwn_item(&create, perm_record)?;
        let request = DwnRequest::new(Type::Private, Action::Create, serde_json::to_vec(&payload)?);
        self.router.handle_request(&request, dids).await?;

        Ok(trimmed_perms)
    }

    async fn private_internal_read(
        &self,
        discover: &SecretKey,
        dids: &[&Did]
    ) -> Result<Vec<DwnItem>, Error> {
        let payload: PrivateReadRequest = SignedObject::from_key(discover, String::new())?;
        let request = DwnRequest::new(Type::Private, Action::Read, serde_json::to_vec(&payload)?);
        Ok(self.router.handle_request(&request, dids).await?.into_iter().flat_map(|data|
            serde_json::from_slice::<DwnItem>(&data).ok()
        ).collect())
    }

    pub async fn private_exists(&self, discover: &SecretKey, dids: &[&Did]) -> Result<bool, Error> {
        Ok(!self.private_internal_read(discover, dids).await?.is_empty())
    }

    pub async fn private_read(
        &self,
        perms: &PermissionSet,
        protocol: Option<&Protocol>,
        dids: &[&Did],
    ) -> Result<(Option<PermissionedRecord>, bool), Error> {
        let discover = perms.discover.public_key();
        let create = perms.create.public_key();
        let read = perms.read.secret_key().ok_or(Error::bad_request(
            "Client.read", "Read Permission Missing"
        ))?;

        let items = self.private_internal_read(&perms.discover, dids).await?;
        let exists = !items.is_empty();
        Ok((items.into_iter().find_map(|item| {
            if let Ok(dc) = read.decrypt(&item.payload) {
                if let Ok(signed) = serde_json::from_slice::<SignedObject<PermissionedRecord>>(&dc) {
                    if let Ok(pr) = signed.verify_with_key(&create) {
                        if let Some(protocol) = protocol.or_else(|| self.get_protocol(&pr.1.protocol).ok()) {
                            let perms = protocol.trim_perms(perms.clone());
                            let delete = perms.delete.as_ref().map(|d| d.public_key());
                            if perms.validate(&pr.0).is_ok() &&
                               protocol.validate(&pr).is_ok() &&
                               item.discover == discover && item.delete == delete {
                                if let Some(perms) = pr.0.combine(perms).ok() {
                                    return Some((perms, pr.1));
                                }
                            }
                        }
                    }
                }
            }
            None
        }), exists))
    }

    pub async fn private_update(
        &self,
        perms: PermissionSet,
        permission_options: &PermissionOptions,
        record: Record,
        dids: &[&Did],
    ) -> Result<PermissionSet, Error> {
        let error = |r: &str| Error::bad_request("Client.update", r);
        let d_error = || error("Delete Permission Missing");

        let create = perms.create.secret_key().ok_or(error("Create Permission Missing"))?;
        let delete = perms.delete.as_ref().ok_or(d_error())?.secret_key().ok_or(d_error())?;

        let (trimmed_perms, perm_record) = self.construct_perm_record(perms, permission_options, record)?;
        let payload: PrivateUpdateRequest = SignedObject::from_key(&delete, Self::construct_dwn_item(&create, perm_record)?)?;
        let request = DwnRequest::new(Type::Private, Action::Update, serde_json::to_vec(&payload)?);

        self.router.handle_request(&request, dids).await?;
        Ok(trimmed_perms)
    }

    pub async fn private_delete(
        &self,
        perms: &PermissionSet,
        dids: &[&Did]
    ) -> Result<(), Error> {
        let error = || Error::bad_request("Client.delete", "Delete Permission Missing");
        let delete = perms.delete.as_ref().ok_or(error())?.secret_key().ok_or(error())?;

        let payload: PrivateDeleteRequest = SignedObject::from_key(&delete, perms.discover.public_key())?;
        let request = DwnRequest::new(Type::Private, Action::Delete, serde_json::to_vec(&payload)?);
        self.router.handle_request(&request, dids).await?;
        Ok(())
    }

    async fn get_next_channel_index(
        &self,
        discover_child: &SecretKey,
        start: usize,
        dids: &[&Did]
    ) -> Result<usize, Error> {
        let mut index = start;
        loop {
            if !self.private_exists(&discover_child.derive_usize(index)?, dids).await? {
                for i in 1..11 {
                    if self.private_exists(&discover_child.derive_usize(index+i)?, dids).await? {
                        index += i;
                        break;
                    }
                    if i == 10 {return Ok(index);}
                }
            }
            index += 1;
        }
    }

    pub async fn private_create_child(
        &self,
        parent: &PermissionedRecord,
        child_protocol: &Hash,
        child_perms: &PermissionSet,
        dids: &[&Did],
    ) -> Result<usize, Error> {
        let error = |r: &str| Error::bad_request("Client.create_child", r);

        let parent_protocol = self.get_protocol(&parent.1.protocol)?;
        parent_protocol.validate_child_protocol(child_protocol)?;

        let parent_perms = &parent.0;

        let channel = parent_perms.channel.as_ref().ok_or(error("Missing Channel Perms"))?;
        let discover_child = channel.discover.secret_key().ok_or(error("Missing DiscoverChild Perms"))?;

        let index = self.get_next_channel_index(&discover_child, 0, dids).await?;//parent.1.get_latest_delete(),
        let discover = discover_child.derive_usize(index)?;
        let create = channel.create.secret_key().ok_or(error("Missing CreateChild Perms"))?;
        let read = channel.read.public_key();

        let protocol = Protocol::channel_item();
        let item_perms = protocol.subset_perms(&PermissionSet::new(
            vec![protocol.hash()],  discover, Key::new_public(create.public_key()), Key::new_public(read), None, None
        ))?;
        let record = (item_perms, Record::new(None, protocol.hash(), serde_json::to_vec(child_perms)?));
        let item = Self::construct_dwn_item(&create, record)?;
        let request = DwnRequest::new(Type::Private, Action::Create, serde_json::to_vec(&item)?);
        self.router.handle_request(&request, dids).await?;

        Ok(index)
    }

    pub async fn private_read_child(
        &self,
        parent: &PermissionedRecord,
        start: Option<usize>,
        end: Option<usize>,
        dids: &[&Did],
    ) -> Result<Vec<PermissionedRecord>, Error> {
        let error = |r: &str| Error::bad_request("Client.read_child", r);
        let start = start.unwrap_or(0);

        let parent_perms = &parent.0;
        let parent_protocol = self.get_protocol(&parent.1.protocol)?;

        let channel = parent_perms.channel.as_ref().ok_or(error("Missing Channel Perms"))?;
        let discover_child = channel.discover.secret_key().ok_or(error("Missing DiscoverChild Perms"))?;
        let create = channel.create.public_key();
        let read = channel.read.secret_key().ok_or(error("Missing ReadChild Perms"))?;
        //let deletes = &parent.1.channel_deletes;

        let item_protocol = Protocol::channel_item();
        let mut item_perms = PermissionSet::new(
            vec![item_protocol.hash()], discover_child.derive_usize(start)?, Key::new_public(create), Key::new_secret(read), None, None
        );

        let mut results = Vec::new();
        let mut index = start;
        let mut empties = 0;
        loop {
            //if deletes.contains(&index) {index += 1; continue;}
            if let Some(end) = end {if index > end {break;}}
            if empties >= 10 {break;}

            item_perms.discover = discover_child.derive_usize(index)?;
            let (perm_item, exists) = self.private_read(&item_perms, Some(&item_protocol), dids).await?;
            if exists {empties = 0} else {empties += 1}

            if let Some(perm_item) = perm_item {
                if let Ok(perm_pointer) = serde_json::from_slice::<PermissionSet>(&perm_item.1.payload) {
                    if let (Some(perm_child), _) = self.private_read(&perm_pointer, None, dids).await? {
                        if parent_protocol.validate_child(&perm_child).is_ok() {
                            results.push(perm_child);
                        }
                    }
                }
            }
            index += 1;
        }

        Ok(results)
    }

    pub async fn dm_create(
        &self,
        sender: &DidKeyPair,
        recipient: &Did,
        permission: PermissionSet,
    ) -> Result<(), Error> {
        let (_, rec_com_key) = self.did_resolver.resolve_dwn_keys(recipient).await?;
        let signed = SignedObject::from_keypair(sender, permission)?;
        let payload = rec_com_key.encrypt(&serde_json::to_vec(&signed)?)?;
        let request: DMCreateRequest = DwnItem::new(rec_com_key, None, payload);
        let request = DwnRequest::new(Type::DM, Action::Create, serde_json::to_vec(&request)?);

        self.router.handle_request(&request, &[recipient]).await?;
        Ok(())
    }

    pub async fn dm_read(
        &self,
        recipient: &DidKeyPair,
        com_key: &SecretKey,
        timestamp: DateTime
    ) -> Result<Vec<(Did, PermissionSet)>, Error> {
        let request: DMReadRequest = SignedObject::from_key(com_key, timestamp)?;
        let request = DwnRequest::new(Type::DM, Action::Read, serde_json::to_vec(&request)?);

        let items = BTreeSet::from_iter(self.router.handle_request(&request, &[&recipient.public.did]).await?
            .into_iter().flat_map(|data|
                serde_json::from_slice::<Vec<DwnItem>>(&data).ok()
            ).flatten()
        ).into_iter().collect::<Vec<DwnItem>>();

        let mut results: Vec<(Did, PermissionSet)> = Vec::new();

        for item in items {
            if item.discover != com_key.public_key() || item.delete.is_some() {continue;}
            if let Ok(dc) = com_key.decrypt(&item.payload) {
                if let Ok(signed) = serde_json::from_slice::<SignedObject<PermissionSet>>(&dc) {
                    if let Ok(Either::Left(sender)) = signed.verify(&*self.did_resolver, None).await {
                        results.push((sender, signed.unwrap()));
                    }
                }
            }
        }
        Ok(results)
    }

    pub async fn public_create(
        &self,
        sig_key: &DidKeyPair,
        record: Record,
        index: Index,
        dids: &[&Did],
    ) -> Result<(), Error> {
        let request: PublicCreateRequest = PublicRecord::new(Either::Left(sig_key.clone()), record, index)?;
        let request = DwnRequest::new(Type::Public, Action::Create, serde_json::to_vec(&request)?);
        self.router.handle_request(&request, dids).await?;
        Ok(())
    }

    pub async fn public_read(
        &self,
        filters: Filters,
        sort_options: Option<SortOptions>,
        dids: &[&Did],
    ) -> Result<Vec<(Verifier, Record)>, Error> {
        let request: PublicReadRequest = (filters, sort_options);
        let request = DwnRequest::new(Type::Public, Action::Read, serde_json::to_vec(&request)?);
        let records: Vec<PublicRecord> = BTreeSet::from_iter(self.router.handle_request(&request, dids).await?.into_iter().flat_map(|data|
            serde_json::from_slice::<Vec<PublicRecord>>(&data).ok()
        ).flatten()).into_iter().collect();
        let mut results = Vec::new();

        //TODO ensure all records match the given filters

        for record in records {
            if let Ok(signer) = record.inner.verify(&*self.did_resolver, None).await {
                let (record, index) = record.inner.unwrap();
                if let Ok(protocol) = self.get_protocol(&record.protocol) {
                    if protocol.validate_payload(&record.payload).is_ok() {
                        results.push((signer, record));
                    }
                }
            }
        }

        Ok(results)
    }

    pub async fn public_update(
        &self,
        sig_key: &DidKeyPair,
        record: Record,
        index: Index,
        dids: &[&Did],
    ) -> Result<(), Error> {
        let request: PublicUpdateRequest = PublicRecord::new(Either::Left(sig_key.clone()), record, index)?;
        let request = DwnRequest::new(Type::Public, Action::Update, serde_json::to_vec(&request)?);
        self.router.handle_request(&request, dids).await?;
        Ok(())
    }

    pub async fn public_delete(
        &self,
        sig_key: &DidKeyPair,
        record_id: Hash,
        dids: &[&Did],
    ) -> Result<(), Error> {
        let request: PublicDeleteRequest = SignedObject::new(Either::Left(sig_key.clone()), record_id)?;
        let request = DwnRequest::new(Type::Public, Action::Delete, serde_json::to_vec(&request)?);
        self.router.handle_request(&request, dids).await?;
        Ok(())
    }

    //PRIVATE
    fn construct_perm_record(
        &self,
        perms: PermissionSet,
        permission_options: &PermissionOptions,
        record: Record,
    ) -> Result<(PermissionSet, PermissionedRecord), Error> {
        let protocol = self.get_protocol(&record.protocol)?;
        let trimmed_perms = protocol.trim_perms(perms);
        let perm_record = (trimmed_perms.clone().subset(permission_options)?, record);
        protocol.validate(&perm_record)?;
        Ok((trimmed_perms, perm_record))
    }

    fn construct_dwn_item(
        create: &SecretKey,
        perm_record: PermissionedRecord,
    ) -> Result<DwnItem, Error> {
        let perms = &perm_record.0;
        let discover = perms.discover.public_key();
        if create.public_key() != perms.create.public_key() {
            return Err(Error::bad_request("Client.internal_create", "Create Permission Does Not Match"));
        }
        let read = perms.read.public_key();
        let delete = perms.delete.clone().map(|d| d.public_key());

        let signed = SignedObject::from_key(create, perm_record)?;
        let payload = read.encrypt(&serde_json::to_vec(&signed)?)?;
        Ok(DwnItem::new(discover, delete, payload))
    }

    fn get_protocol(&self, protocol: &Hash) -> Result<&Protocol, Error> {
        if let Some(sys_p) = self.sys_protocols.get(protocol) {return Ok(sys_p);}
        self.protocols.get(protocol).ok_or(Error::bad_request("Client.get_protocol", "Protocol not configured"))
    }
}
