use super::Error;

use crate::dids::{DefaultDidResolver, DidResolver, Did};
use crate::dids::signing::Verifier;

use super::structs::{PermissionedRecord, ProtocolFetcher};
use super::permission::{PermissionOptions, PermissionSet};
use super::{PrivateClient, PublicClient, DMClient};
use super::protocol::{SystemProtocols, Protocol};
use super::structs::{AgentKey, Record};
use super::router::DefaultRouter;
use super::traits::Router;

use std::path::PathBuf;

use simple_crypto::{PublicKey, Hashable};
use simple_database::database::{SortOptions, Filter, FiltersBuilder,Filters, Index};
use simple_database::KeyValueStore;
use chrono::{DateTime, Utc};
use either::Either;
use uuid::Uuid;

const LAST_DM_CHECK: [u8; 13] = *b"LAST_DM_CHECK";

#[derive(Clone)]
pub struct Agent {
    tenant: Did,
    agent_key: AgentKey,
    private_client: PrivateClient,
    public_client: PublicClient,
    dm_client: DMClient,
    cache: Box<dyn KeyValueStore>
}

impl Agent {
    pub async fn new<KVS: KeyValueStore + 'static>(
        agent_key: AgentKey,
        protocols: Vec<Protocol>,
        path: Option<PathBuf>,
        did_resolver: Option<Box<dyn DidResolver>>,
        router: Option<Box<dyn Router>>,
    ) -> Result<Self, Error> {
        let path = path.unwrap_or(PathBuf::from("Agent"));
        let did_resolver = did_resolver.unwrap_or(Box::new(DefaultDidResolver::new::<KVS>(Some(path.join("DefaultDidResolver"))).await?));
        let router = router.unwrap_or(Box::new(DefaultRouter::new(did_resolver.clone(), None)));
        let protocol_fetcher = ProtocolFetcher::new([vec![SystemProtocols::protocol_folder(agent_key.master_protocol)], protocols].concat());
        let private_client = PrivateClient::new(router.clone(), protocol_fetcher.clone());
        let public_client = PublicClient::new(Either::Left(agent_key.sig_key.clone()), router.clone(), did_resolver.clone(), protocol_fetcher.clone());
        let dm_client = DMClient::new(agent_key.sig_key.clone(), agent_key.com_key.key.clone(), router.clone(), did_resolver.clone());
        let cache = Box::new(KVS::new(path.join("AgentCache")).await?);

        Ok(Agent{
            tenant: agent_key.sig_key.public.did.clone(),
            agent_key,
            private_client,
            public_client,
            dm_client,
            cache,
        })
    }

    pub fn get_root(&self) -> &Vec<Uuid> {&self.agent_key.enc_key.path}

    pub fn tenant(&self) -> &Did {&self.tenant}

    pub async fn create(
        &self,
        parent_path: &[Uuid],
        permission_options: Option<&PermissionOptions>,
        record: Record,
        dids: Option<&[&Did]>,
    ) -> Result<Vec<Uuid>, Error> {
        let default_dids = vec![self.tenant()];
        let dids = dids.unwrap_or(&default_dids);
        let error = |r: &str| Error::bad_request("Agent.create", r);
        let record_path = [parent_path.to_vec(), vec![record.record_id]].concat();
        let record_perms = self.get_permission(&record_path)?;
        let perm_parent = self.private_client.read(&self.get_permission(parent_path)?, dids).await?.ok_or(error("Parent could not be found"))?;
        let perms = self.private_client.create(record_perms, permission_options, record, dids).await?;
        let record = Record::new(None, &SystemProtocols::perm_pointer(), serde_json::to_vec(&perms)?);
        self.private_client.create_child(&perm_parent, record, dids).await?;
        Ok(record_path)
    }

    pub async fn read(
        &self,
        path: &[Uuid],
        index: Option<(usize, Option<usize>)>,
        dids: Option<&[&Did]>
    ) -> Result<Option<Record>, Error> {
        let default_dids = vec![self.tenant()];
        let dids = dids.unwrap_or(&default_dids);
        let perms = self.get_permission(path)?;
        if let Some(record) = self.private_client.read(&perms, dids).await? {
            if let Some((start, end)) = index {
                Ok(self.private_client.read_child(&record, Some(start), end, dids).await?.0.first().map(|pr| pr.0.record.clone()))
            } else {
                Ok(Some(record.record))
            }
        } else {
            Ok(None)
        }
    }

    pub async fn update(
        &self,
        path: &[Uuid],
        permission_options: Option<&PermissionOptions>,
        record: Record,
        dids: Option<&[&Did]>,
    ) -> Result<(), Error> {
        let default_dids = vec![self.tenant()];
        let dids = dids.unwrap_or(&default_dids);
        let perms = self.get_permission(path)?;
        self.private_client.update(perms, permission_options, record, dids).await?;
        Ok(())
    }

    pub async fn delete(
        &self,
        path: &[Uuid],
        dids: Option<&[&Did]>,
    ) -> Result<bool, Error> {
        let default_dids = vec![self.tenant()];
        let dids = dids.unwrap_or(&default_dids);
        if let Some(record) = self.private_client.read(&self.get_permission(path)?, dids).await? {
            self.private_client.delete(&record.perms, dids).await?;
            Ok(true)
        } else {Ok(false)}
    }

    pub async fn share(
        &self,
        path: &[Uuid],
        permission_options: &PermissionOptions,
        recipient: &Did
    ) -> Result<(), Error> {
        let channel = self.establish_direct_messages(recipient).await?;

        let filters = FiltersBuilder::build(vec![
            ("author", Filter::equal(recipient.to_string())),
            ("type", Filter::equal("agent_keys".to_string()))
        ]);

        let perms = serde_json::to_vec(&self.get_permission(path)?.subset(permission_options)?)?;

        let agent_keys = self.public_read(filters, None, Some(&[recipient])).await?.first().and_then(|(_, record)|
            serde_json::from_slice::<Vec<PublicKey>>(&record.payload).ok()
        ).ok_or(Error::bad_request("Agent.share", "Recipient has no agents"))?
        .into_iter().map(|key| Ok(key.encrypt(&perms)?)).collect::<Result<Vec<Vec<u8>>, Error>>()?;
        let record = Record::new(None, &SystemProtocols::shared_pointer(), serde_json::to_vec(&agent_keys)?);
        self.private_client.create_child(
            &channel,
            record,
            &[self.tenant(), recipient]
        ).await?;
        Ok(())
    }

    pub async fn scan(&self) -> Result<(), Error> {
        let dids = [self.tenant()];
        self.check_did_messages().await?;
        let root = self.private_client.read(&PermissionSet::from_key(&self.agent_key.com_key)?, &dids).await?
                .ok_or(Error::bad_request("Agent.establish_direct_messages", "Parent Not Found"))?;
        let channels = self.private_client.read_child(&root, None, None, &dids).await?.0;

        for (channel, index) in channels {
            let ldi_id = Uuid::new_v5(&Uuid::NAMESPACE_OID,
                &serde_json::to_vec(&format!("LAST_DM_INDEX: {} {}",
                    serde_json::to_vec(&self.agent_key.com_key.path)?.hash(),
                    index
                ))?
            );
            let ldi_perms = PermissionSet::from_key(&self.agent_key.com_key.derive_path(&[ldi_id])?)?;
            let last_dm_index = self.private_client.read(&ldi_perms, &dids).await?.map(|record|
                serde_json::from_slice::<usize>(&record.record.payload)
            ).transpose()?;
            let (records, last_dm_index) = self.private_client.read_child(&channel, last_dm_index, None, &dids).await?;

            for (channel_item, _) in records {
                let agent_payloads = serde_json::from_slice::<Vec<Vec<u8>>>(&channel_item.record.payload)?;
                if let Some(sent_perms) = agent_payloads.into_iter().find_map(|p|
                    self.agent_key.enc_key.key.decrypt(&p).ok().and_then(|p|
                        serde_json::from_slice::<PermissionSet>(&p).ok()
                    )
                ) {
                    if self.private_client.read(&sent_perms, &dids).await?.is_some() {
                        if let Ok(my_perms) = self.get_permission(&sent_perms.path) {
                            if let (Some(record), _) = self.private_client.internal_read(&my_perms, None, &dids).await? {
                                if record.record.protocol == SystemProtocols::pointer().hash() {
                                    let perms = serde_json::from_slice::<PermissionSet>(&record.record.payload)?;
                                    if let Ok(perms) = perms.combine(sent_perms) {
                                        let mut record = record.record;
                                        record.payload = serde_json::to_vec(&perms)?;
                                        self.private_client.update(my_perms, None, record, &dids).await?;
                                    }
                                }
                            } else {
                                let parent_path = &sent_perms.path[..sent_perms.path.len()-1];
                                if let Ok(my_parent_perms) = self.get_permission(parent_path) {
                                    if let Ok(Some(perm_parent)) = self.private_client.read(&my_parent_perms, &dids).await {
                                        let record = Record::new(None, &SystemProtocols::pointer(), serde_json::to_vec(&sent_perms)?);
                                        let perms = self.private_client.create(my_perms, None, record, &dids).await?;
                                        let record = Record::new(None, &SystemProtocols::perm_pointer(), serde_json::to_vec(&perms)?);
                                        self.private_client.create_child(&perm_parent, record, &dids).await?;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            let record = Record::new(Some(ldi_id), &SystemProtocols::usize(), serde_json::to_vec(&last_dm_index)?);
            self.private_client.update(ldi_perms, None, record, &dids).await?;
        }
        Ok(())
    }

    pub async fn public_create(
        &self,
        record: Record,
        index: Index,
        dids: Option<&[&Did]>
    ) -> Result<(), Error> {
        let default_dids = vec![self.tenant()];
        let dids = dids.unwrap_or(&default_dids);
        self.public_client.create(record, index, dids).await
    }

    pub async fn public_read(
        &self,
        filters: Filters,
        sort_options: Option<SortOptions>,
        dids: Option<&[&Did]>
    ) -> Result<Vec<(Verifier, Record)>, Error> {
        let default_dids = vec![self.tenant()];
        let dids = dids.unwrap_or(&default_dids);
        self.public_client.read(filters, sort_options, dids).await
    }

    pub async fn public_update(
        &self,
        record: Record,
        index: Index,
        dids: Option<&[&Did]>
    ) -> Result<(), Error> {
        let default_dids = vec![self.tenant()];
        let dids = dids.unwrap_or(&default_dids);
        self.public_client.update(record, index, dids).await
    }

    pub async fn public_delete(
        &self,
        record_id: Uuid,
        dids: Option<&[&Did]>
    ) -> Result<(), Error> {
        let default_dids = vec![self.tenant()];
        let dids = dids.unwrap_or(&default_dids);
        self.public_client.delete(record_id, dids).await
    }

    async fn establish_direct_messages(&self, recipient: &Did) -> Result<PermissionedRecord, Error> {
        self.check_did_messages().await?;
        let dids = [recipient, self.tenant()];
        let recipient_id = Uuid::new_v5(&Uuid::NAMESPACE_OID, &recipient.hash_bytes());
        let perms = PermissionSet::from_key(&self.agent_key.com_key.derive_path(&[recipient_id])?)?;
        if let Some(perm_record) = self.private_client.read(&perms, &dids).await? {
            Ok(perm_record)
        } else {
            let record = Record::new(Some(recipient_id), &SystemProtocols::dms_channel(), Vec::new());

            let perm_parent = self.private_client.read(&PermissionSet::from_key(&self.agent_key.com_key)?, &dids).await?
                .ok_or(Error::bad_request("Agent.establish_direct_messages", "Parent Not Found"))?;
            let perms = self.private_client.create(perms.clone(), None, record, &dids).await?;
            let record = Record::new(None, &SystemProtocols::perm_pointer(), serde_json::to_vec(&perms)?);
            self.private_client.create_child(&perm_parent, record, &[self.tenant()]).await?;

            self.dm_client.create(recipient, perms.clone()).await?;
            Ok(self.private_client.read(&perms, &dids).await?.ok_or(
                Error::bad_request("Agent.establish_direct_messages", "Could not create record")
            )?)
        }
    }

    async fn check_did_messages(&self) -> Result<(), Error> {
        let dids = [self.tenant()];
        let ldc_id = Uuid::new_v5(&Uuid::NAMESPACE_OID, &LAST_DM_CHECK);
        let ldc_perms = PermissionSet::from_key(&self.agent_key.com_key.derive_path(&[ldc_id])?)?;
        let last_dm_check = self.private_client.read(&ldc_perms, &dids).await?.map(|record|
            serde_json::from_slice::<DateTime<Utc>>(&record.record.payload)
        ).transpose()?.unwrap_or_default();

        for (sender, permission) in self.dm_client.read(last_dm_check).await? {
            if let Some(pr) = self.private_client.read(&permission, &dids).await? {
                let sender_id = Uuid::new_v5(&Uuid::NAMESPACE_OID, &sender.hash_bytes());
                let record = Record::new(Some(sender_id), &SystemProtocols::pointer(), serde_json::to_vec(&pr.perms)?);
                let channel_perms = PermissionSet::from_key(&self.agent_key.com_key.derive_path(&[sender_id])?)?;

                let perm_parent = self.private_client.read(&PermissionSet::from_key(&self.agent_key.com_key)?, &dids).await?
                    .ok_or(Error::bad_request("Agent.check_did_messages", "Parent Not Found"))?;

                let perms = self.private_client.update(channel_perms, None, record, &dids).await?;
                //let perms = self.private_client.create(perms.clone(), None, record, &dids).await?;

                let record = Record::new(None, &SystemProtocols::perm_pointer(), serde_json::to_vec(&perms)?);
                self.private_client.create_child(&perm_parent, record, &dids).await?;
            }
        }
        let record = Record::new(Some(ldc_id), &SystemProtocols::date_time(), serde_json::to_vec(&Utc::now())?);
        self.private_client.update(ldc_perms, None, record, &dids).await?;
        Ok(())
    }

    fn get_permission(&self, path: &[Uuid]) -> Result<PermissionSet, Error> {
        PermissionSet::from_key(&self.agent_key.enc_key.derive_path(path)?)
    }
}

impl std::fmt::Debug for Agent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Agent")
        //.field("tenant", self.tenant().to_string())
        .finish()
    }
}
