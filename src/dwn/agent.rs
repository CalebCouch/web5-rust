use super::Error;
use crate::common::traits::KeyValueStore;
use crate::common::structs::DateTime;
use crate::common::Database;
use crate::crypto::secp256k1::SecretKey;
use crate::crypto::structs::Hash;
use crate::crypto::traits::Hashable;
use crate::dids::structs::{
    DidResolver as DefaultDidResolver,
    DidKeyPair,
    Did,
};
use crate::dids::traits::DidResolver;
use super::structs::{PermissionedRecord, Record};
use super::permission::Permission;
use super::traits::{Client, P2P};
use super::protocol::Protocol;
use super::DwnClient;
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct PPG {key: SecretKey}
impl P2P for PPG {
    fn p_to_p(&self, protocol: &Hash) -> Result<Permission, Error> {
        Permission::from_key(&self.key.derive_hash(protocol)?)
    }
}

pub struct Agent {
    pub keypair: DidKeyPair,
    pub database: Database,
    pub metadata: Box<dyn KeyValueStore>,
    pub did_resolver: Box<dyn DidResolver>,
    pub client: Box<dyn Client>
}

impl Agent {
    pub async fn new<KVS: KeyValueStore + 'static>(
        keypair: DidKeyPair,
        data_path: Option<PathBuf>,
        did_resolver: Option<Box<dyn DidResolver>>,
        client: Option<Box<dyn Client>>,
    ) -> Result<Self, Error> {
        let data_path = data_path.unwrap_or(PathBuf::from("AGENT"));
        let did_resolver = did_resolver.unwrap_or(Box::new(DefaultDidResolver::new()));
        let client = client.unwrap_or(Box::new(DwnClient::new::<KVS>(
            keypair.public.did.clone(),
            None, None, did_resolver.clone(),
            Box::new(PPG{key: keypair.secret.clone()})
        )?));
        Ok(Agent{
            keypair,
            database: Database::new::<KVS>(data_path.join("DATABASE"))?,
            metadata: Box::new(KVS::new(data_path.join("METADATA"))?),
            did_resolver,
            client,
        })
    }

    pub fn tenant(&self) -> Did {self.keypair.public.did.clone()}

    pub fn record_key(&self, record_id: &Hash) -> Result<SecretKey, Error> {
        self.keypair.secret.derive_hash(record_id)
    }

    pub fn get_permission(&self, record_id: &Hash) -> Result<Permission, Error> {
        Permission::from_key(&self.record_key(record_id)?)
    }

    pub async fn configure_protocol(&mut self, protocol: Protocol) -> Result<(), Error> {
        self.client.configure_protocol(protocol).await
    }

    pub async fn create(
        &mut self,
        parent_id: Option<&Hash>,
        record: Record,
        dids: &[&Did],
    ) -> Result<Permission, Error> {
        let perms = self.get_permission(&record.record_id)?;
        let child_perms = self.client.create(&perms, record, dids).await?;
        Ok(if let Some(parent_id) = parent_id {
            let parent = self.read(parent_id, dids).await?.ok_or(Error::not_found("Agent.create", "Could not find Parent"))?;
            self.client.create_child(&parent.0, parent.1.get_latest_delete(), child_perms, dids).await?.0
        } else {child_perms})
    }

    pub async fn create_if_not_exists(
        &mut self,
        record: Record,
        dids: &[&Did]
    ) -> Result<PermissionedRecord, Error> {
        Ok(if let Some(perm_record) = self.read(&record.record_id, dids).await? {
            if perm_record.1 != record {return Err(Error::bad_request(
                "Agent.create_if_not_exists", "Existing record does not match"
            ));}
            perm_record
        } else {
            (self.create(None, record.clone(), dids).await?, record)
        })
    }

    pub async fn read(
        &mut self,
        record_id: &Hash,
        dids: &[&Did]
    ) -> Result<Option<PermissionedRecord>, Error> {
        let perms = self.get_permission(record_id)?;
        if let Some(perm_record) = self.client.read(&perms, dids, true).await? {
            if perm_record.1.record_id != *record_id {return Err(Error::bad_request(
                "Agent.read", "record_id returned a record with a different Record Id"
            ));}
            Ok(Some(perm_record))
        } else {Ok(None)}
    }

    pub async fn update(
        &mut self,
        record: Record,
        dids: &[&Did],
    ) -> Result<Permission, Error> {
        let perms = self.get_permission(&record.record_id)?;
        let perms = self.read(&record.record_id, dids).await?.map(|r| r.0).unwrap_or(perms);
        self.client.update(&perms, record, dids).await
    }

    pub async fn delete(
        &mut self,
        record_id: &Hash,
        dids: &[&Did],
    ) -> Result<(), Error> {
        let (perms, _) = self.read(record_id, dids).await?.ok_or(Error::not_found("Agent.update", "Could not find Record"))?;
        self.client.delete(&perms, dids).await
    }

    pub async fn read_child(
        &mut self,
        parent_id: &Hash,
        index: usize,
        dids: &[&Did]
    ) -> Result<Option<PermissionedRecord>, Error> {
        Ok(self.read_children(parent_id, index, Some(index+1), dids).await?.first().cloned())
    }

    pub async fn read_children(
        &mut self,
        parent_id: &Hash,
        start: usize,
        end: Option<usize>,
        dids: &[&Did],
    ) -> Result<Vec<PermissionedRecord>, Error> {
        let (perms, _) = self.read(parent_id, dids).await?.ok_or(Error::not_found("Agent.read_children", "Parent could not be found"))?;
        self.client.read_child(&perms, start, end, dids).await
    }

    pub async fn delete_child(
        &mut self,
        parent_id: &Hash,
        index: usize,
        dids: &[&Did]
    ) -> Result<(), Error> {
        let (perms, _) = self.read(parent_id, dids).await?.ok_or(Error::not_found("Agent.read_children", "Parent could not be found"))?;
        self.client.delete_child(&perms, index, dids).await
    }


    pub async fn send_dm(&mut self, recipient: &Did, permission: Permission) -> Result<(), Error> {
        let pr = self.establish_dms(recipient).await?;
        self.client.create_child(&pr.0, pr.1.get_latest_delete(), permission, &[recipient, &self.tenant()]).await?;
        Ok(())
    }

    pub async fn read_dms(&mut self, recipient: &Did, start: usize, end: Option<usize>) -> Result<Vec<PermissionedRecord>, Error> {
        let pr = self.establish_dms(recipient).await?;
        self.client.read_child(&pr.0, start, end, &[recipient, &self.tenant()]).await
    }

    pub async fn establish_dms(&mut self, recipient: &Did) -> Result<PermissionedRecord, Error> {
        self.check_did_messages().await?;
        let payload = serde_json::to_vec(recipient)?;
        let record_id = payload.hash();
        let perm = self.get_permission(&record_id)?;
        Ok(if let Some(perm_record) = self.client.read(&perm, &[recipient, &self.tenant()], true).await? {
            perm_record
        } else {
            let record = Record::new(Some(record_id), Protocol::dms_channel().hash(), payload);
            let perms = self.create(None, record, &[recipient, &self.tenant()]).await?;
            self.client.create_did_msg(&self.keypair, recipient, perms).await?;
            self.read(&record_id, &[&self.tenant()]).await?.ok_or(Error::err(
                "Agent.establish_dms", "Failed to create dm channel"
            ))?
        })
    }

    pub async fn check_did_messages(&mut self) -> Result<(), Error> {
        let ldc_id = serde_json::to_vec("LAST_DM_CHECK")?.hash();
        let last_dm_check = self.read(&ldc_id, &[&self.tenant()]).await?.map(|record|
            serde_json::from_slice::<DateTime>(&record.1.payload)
        ).transpose()?.unwrap_or_default();
        //TODO: if last dm check was in the last 5-10 minutes return ok

        for (sender, permission) in self.client.read_did_msgs((&self.tenant(), &self.keypair.secret), last_dm_check).await? {
            if let Some(pr) = self.client.read(&permission, &[&sender, &self.tenant()], false).await? {
                if pr.1.protocol == Protocol::dms_channel().hash() {
                    let record = Record::new(Some(serde_json::to_vec(&sender)?.hash()), Protocol::permission_grant().hash(), serde_json::to_vec(&pr.0)?);
                    self.update(record, &[&self.tenant()]).await?;
                }
            }
        }
        let record = Record::new(Some(ldc_id), Protocol::file().hash(), serde_json::to_vec(&DateTime::now())?);
        self.update(record, &[&self.tenant()]).await?;
        Ok(())
    }
}

impl std::fmt::Debug for Agent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Agent")
        .field("tenant", &self.keypair.public.did.to_string())
//      .field("Records",
//          &self.database.query::<SignedObject<Record>>(None, &Filters::default(), None).unwrap().0.iter().map(|r| {
//              (
//                  format!("record_id: {}", r.inner().record_id().to_string()),
//                  r.secondary_keys()
//              )
//          }).collect::<Vec<(String, Index)>>()
//      )
        .finish()
    }
}
