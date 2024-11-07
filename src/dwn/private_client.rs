use super::Error;

use super::structs::{
    PrivateCreateRequest,
    PrivateUpdateRequest,
    PrivateDeleteRequest,
    PrivateReadRequest,
    PermissionedRecord,
    ProtocolFetcher,
    DwnRequest,
    DwnItem,
    Record,
    Action,
    Type
};

use super::permission::{PermissionSet, PermissionOptions};
use super::protocol::{SystemProtocols, Protocol};
use super::traits::Router;

use simple_crypto::{SecretKey, Key, Hashable, Hash};

use crate::dids::signing::SignedObject;
use crate::dids::Did;


#[derive(Debug, Clone)]
pub struct PrivateClient {
    router: Box<dyn Router>,
    protocol_fetcher: ProtocolFetcher,
}

impl PrivateClient {
    pub fn new(
        router: Box<dyn Router>,
        protocol_fetcher:  ProtocolFetcher,
    ) -> Self {
        PrivateClient{router, protocol_fetcher}
    }

    pub async fn create(
        &self,
        perms: PermissionSet,
        permission_options: Option<&PermissionOptions>,
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

    pub async fn read(
        &self,
        perms: &PermissionSet,
        dids: &[&Did]
    ) -> Result<Option<PermissionedRecord>, Error> {
        Ok(self.resolve_pointers(perms, dids).await?.0)
    }

    pub async fn resolve_pointers(
        &self,
        perms: &PermissionSet,
        dids: &[&Did]
    ) -> Result<(Option<PermissionedRecord>, bool), Error> {
        let (perm_record, exists) = self.internal_read(perms, None, dids).await?;
        if let Some(perm_record) = perm_record {
            if perm_record.record.protocol == SystemProtocols::pointer().hash() || perm_record.record.protocol == SystemProtocols::perm_pointer().hash() {
                let pointer_perms = serde_json::from_slice::<PermissionSet>(&perm_record.record.payload)?;
                if let (Some(pr), _) = Box::pin(self.resolve_pointers(&pointer_perms, dids)).await? {
                    return Ok((Some(pr), exists));
                } else {
                    //If pointer points to nothing delete the pointer
                    self.delete(perms, dids).await?;
                }
            } else {
                let record = PermissionedRecord::new(perm_record.perms.combine(perms.clone())?, perm_record.record);
                return Ok((Some(record), exists));
            }
        }
        Ok((None, exists))
    }

    pub async fn update(
        &self,
        perms: PermissionSet,
        permission_options: Option<&PermissionOptions>,
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

    pub async fn delete(
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

    pub async fn create_child(
        &self,
        parent: &PermissionedRecord,
        record: Record,
        dids: &[&Did],
    ) -> Result<usize, Error> {
        let error = |r: &str| Error::bad_request("Client.create_child", r);

        let parent_perms = &parent.perms;

        let channel = parent_perms.channel.as_ref().ok_or(error("Missing Channel Perms"))?;
        let discover_child = channel.discover.secret_key().ok_or(error("Missing DiscoverChild Perms"))?;

        let index = self.get_next_channel_index(&discover_child, 0, dids).await?;//parent.1.get_latest_delete(),
        let discover = discover_child.derive_usize(index)?;
        let create = channel.create.secret_key().ok_or(error("Missing CreateChild Perms"))?;

        let protocol = self.protocol_fetcher.get(&record.protocol)?;
        let item_perms = PermissionSet::new(
            vec![b"channelitem".to_vec().hash()], discover, channel.create.clone(), channel.read.clone(), None, None
        ).get_min_perms(protocol)?;
        let record = PermissionedRecord::new(item_perms, record);
        let item = Self::construct_dwn_item(&create, record)?;
        let request = DwnRequest::new(Type::Private, Action::Create, serde_json::to_vec(&item)?);
        self.router.handle_request(&request, dids).await?;

        Ok(index)
    }

    pub async fn read_child(
        &self,
        parent: &PermissionedRecord,
        start: Option<usize>,
        end: Option<usize>,
        dids: &[&Did],
    ) -> Result<(Vec<(PermissionedRecord, usize)>, usize), Error> {
        let error = |r: &str| Error::bad_request("Client.read_child", r);
        let start = start.unwrap_or(0);

        let parent_perms = &parent.perms;
        let parent_protocol = self.protocol_fetcher.get(&parent.record.protocol)?;

        let channel = parent_perms.channel.as_ref().ok_or(error("Missing Channel Perms"))?;
        let discover_child = channel.discover.secret_key().ok_or(error("Missing DiscoverChild Perms"))?;
        let create = channel.create.public_key();
        let read = channel.read.secret_key().ok_or(error("Missing ReadChild Perms"))?;

        let mut item_perms = PermissionSet::new(
            vec![b"channelitem".to_vec().hash()], discover_child.derive_usize(start)?, Key::new_public(create), Key::new_secret(read), None, None
        );

        let mut results = Vec::new();
        let mut index = start;
        let mut empties = 0;
        loop {
            if let Some(end) = end {if index > end {break;}}
            if empties >= 10 {break;}

            item_perms.discover = discover_child.derive_usize(index)?;
            let (perm_item, exists) = self.resolve_pointers(&item_perms, dids).await?;
            if exists {empties = 0} else {empties += 1}

            if let Some(perm_item) = perm_item {
                if perm_item.is_valid_child(parent_protocol).is_ok() {
                    results.push((perm_item, index));
                }
            }
            index += 1;
        }

        Ok((results, end.unwrap_or_else(|| index-10)))
    }

    async fn fetch(
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

    pub async fn internal_read(
        &self,
        perms: &PermissionSet,
        protocol: Option<&Protocol>,
        dids: &[&Did],
    ) -> Result<(Option<PermissionedRecord>, bool), Error> {
        if perms.path.is_empty() {return Ok((Some(self.init_root(perms.clone())), true));}

        let discover = perms.discover.public_key();
        let create = perms.create.public_key();
        let read = perms.read.secret_key().ok_or(Error::bad_request(
            "Client.read", "Read Permission Missing"
        ))?;

        let items = self.fetch(&perms.discover, dids).await?;
        let exists = !items.is_empty();
        Ok((items.into_iter().find_map(|item| {
            if let Ok(dc) = read.decrypt(&item.payload) {
                if let Ok(signed) = serde_json::from_slice::<SignedObject<PermissionedRecord>>(&dc) {
                    if let Ok(pr) = signed.verify_with_key(&create) {
                        if let Some(protocol) = protocol.or_else(|| self.protocol_fetcher.get(&pr.record.protocol).ok()) {
                            let perms = perms.clone().trim(protocol);
                            let delete = perms.delete.as_ref().map(|d| d.public_key());
                            if perms.validate(&pr.perms).is_ok() &&
                               pr.validate(protocol).is_ok() &&
                               item.discover == discover && item.delete == delete {
                                if let Ok(perms) = pr.perms.combine(perms) {
                                    return Some(PermissionedRecord::new(perms, pr.record));
                                }
                            }
                        }
                    }
                }
            }
            None
        }), exists))
    }

    async fn exists(&self, discover: &SecretKey, dids: &[&Did]) -> Result<bool, Error> {
        Ok(!self.fetch(discover, dids).await?.is_empty())
    }

    async fn get_next_channel_index(
        &self,
        discover_child: &SecretKey,
        start: usize,
        dids: &[&Did]
    ) -> Result<usize, Error> {
        let mut index = start;
        loop {
            if !self.exists(&discover_child.derive_usize(index)?, dids).await? {
                for i in 1..11 {
                    if self.exists(&discover_child.derive_usize(index+i)?, dids).await? {
                        index += i;
                        break;
                    }
                    if i == 10 {return Ok(index);}
                }
            }
            index += 1;
        }
    }

    //Root always has full permissions never will anyone obtain read only root perms
    fn init_root(
        &self,
        perms: PermissionSet,
    ) -> PermissionedRecord {
        let protocol = SystemProtocols::root();
        let root_record = Record::new(Some(Hash::all_zeros()), &protocol, Vec::new());
        PermissionedRecord::new(perms.trim(&protocol), root_record)
    }

    fn construct_perm_record(
        &self,
        perms: PermissionSet,
        permission_options: Option<&PermissionOptions>,
        record: Record,
    ) -> Result<(PermissionSet, PermissionedRecord), Error> {
        let protocol = self.protocol_fetcher.get(&record.protocol)?;
        let permission_options = permission_options.unwrap_or(&protocol.permissions);
        let trimmed_perms = perms.trim(protocol);
        let perm_record = PermissionedRecord::new(trimmed_perms.clone().subset(permission_options)?, record);
        perm_record.validate(protocol)?;
        Ok((trimmed_perms, perm_record))
    }

    fn construct_dwn_item(
        create: &SecretKey,
        perm_record: PermissionedRecord,
    ) -> Result<DwnItem, Error> {
        let perms = &perm_record.perms;
        let discover = perms.discover.public_key();
        if create.public_key() != perms.create.public_key() {
            return Err(Error::bad_request("Client.construct_dwn_item", "Create Permission Does Not Match"));
        }
        let read = perms.read.public_key();
        let delete = perms.delete.clone().map(|d| d.public_key());

        let signed = SignedObject::from_key(create, perm_record)?;
        let payload = read.encrypt(&serde_json::to_vec(&signed)?)?;
        Ok(DwnItem::new(discover, delete, payload))
    }
}
