use super::Error;

use super::structs::PermissionedRecord;
use super::permission::{
    ChannelPermissionOptions,
    PermissionOptions,
    Permission,
};

use crate::common::traits::Indexable;
use crate::common::structs::Schemas;

use crate::crypto::traits::{Hashable};
use crate::crypto::structs::Hash;

use crate::dids::structs::Did;

use std::collections::BTreeMap;

use schemars::{JsonSchema, schema_for};
use jsonschema::JSONSchema;
use serde::{Serialize, Deserialize};

#[derive(JsonSchema, Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ChannelProtocol {
    pub child_protocols: Option<Vec<Hash>>, //None for any child empty for no children
    pub delete: bool, //Weather child items can be deleted
}
impl ChannelProtocol {
    pub fn new(child_protocols: Option<Vec<Hash>>, delete: bool) -> Self {
        ChannelProtocol{child_protocols, delete}
    }
}

#[derive(JsonSchema, Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Protocol {
    pub delete: bool,//Weather record can be deleted
    pub permissions: PermissionOptions,
    pub schema: Option<String>,
    pub channel: Option<ChannelProtocol>
}

impl Hashable for Protocol {}
impl Indexable for Protocol {}

impl Protocol {

    //BUILT-IN PROTOCOLS
    pub fn system_protocols() -> BTreeMap<Hash, Self> {
        let cp = Self::configure_protocol();
        let ci = Self::channel_item();
        let pg = Self::permission_grant();
        let fi = Self::file();
        let fo = Self::folder();
        let dm = Self::dms_channel();
        BTreeMap::from([
            (cp.hash(), cp),
            (ci.hash(), ci),
            (pg.hash(), pg),
            (fi.hash(), fi),
            (fo.hash(), fo),
            (dm.hash(), dm)
        ])
    }

    pub fn folder() -> Self {
        Protocol {
            delete: true,
            permissions: PermissionOptions::new(false, false, false, Some(
                ChannelPermissionOptions::new(false, false, false)
            )),
            schema: Some(serde_json::to_string(&schema_for!(String)).unwrap()),
            channel: Some(ChannelProtocol::new(None, true))
        }
    }

    pub fn configure_protocol() -> Self {
        Protocol {
            delete: true,
            permissions: PermissionOptions::new(false, true, false, None),
            schema: Some(serde_json::to_string(&schema_for!(Protocol)).unwrap()),
            channel: None
        }
    }

    pub fn channel_item() -> Self {
        Protocol {
            delete: false,
            permissions: PermissionOptions::new(false, false, false, None),
            schema: Some(serde_json::to_string(&schema_for!(Permission)).unwrap()),
            channel: None
        }
    }

    pub fn permission_grant() -> Self {
        Protocol {
            delete: true,
            permissions: PermissionOptions::new(false, true, false, None),
            schema: Some(serde_json::to_string(&schema_for!(Permission)).unwrap()),
            channel: None
        }
    }

    pub fn file() -> Self {
        Protocol {
            delete: true,
            permissions: PermissionOptions::new(false, false, false, None),
            schema: Some(serde_json::to_string(&Schemas::any()).unwrap()),
            channel: None
        }
    }

    pub fn dms_channel() -> Self {
        Protocol {
            delete: false,
            permissions: PermissionOptions::new(false, true, false, Some(
                ChannelPermissionOptions::new(true, true, true)
            )),
            schema: Some(serde_json::to_string(&schema_for!(Did)).unwrap()),
            channel: Some(ChannelProtocol::new(None, false))
        }
    }

    pub fn is_sys_protocol(&self) -> bool {
        Self::system_protocols().remove(&self.hash()).is_some()
    }

    pub fn trim_perms(&self, perms: &Permission) -> Result<Permission, Error> {
        let mut perms = perms.clone();
        if !self.delete {perms.delete = None;}
        if self.channel.is_none() {perms.channel = None;}
        perms.subset(&self.permissions)
    }

    pub fn validate_child(&self, perm_record: &PermissionedRecord) -> Result<(), Error> {
        let error = |r: &str| Error::bad_request("Protocol.validate_child", r);
        if let Some(channel) = &self.channel {
            if let Some(cps) = &channel.child_protocols {
                if !cps.contains(&perm_record.1.protocol) {
                    return Err(error("ChildProtocol not supported by channel"));
                }
            }
            Ok(())
        } else {Err(error("Protocol Has No Channel"))}
    }

    pub fn validate(&self, permissioned_record: &PermissionedRecord) -> Result<(), Error> {
        let error = |r: &str| Error::bad_request("Protocol.validate", r);
        let (perms, record) = permissioned_record;
        self.validate_self()?;
        let trimmed_perms = self.trim_perms(perms).or(Err(error(
            "Permission could not meet minimum permission requirements"
        )))?;
        if *perms != trimmed_perms {
            return Err(error("Permission exceeded required permissions"));
        }
        if self.hash() != record.protocol {
            return Err(error("Record does not use this protocol"));
        }
        self.validate_payload(&record.payload)?;
        if if let Some(c) = &self.channel {!c.delete} else {true} && !record.channel_deletes.is_empty() {
            return Err(error("Record contains delete child elements but deletes are not enabled"));
        }
        Ok(())
    }

    pub fn validate_self(&self) -> Result<(), Error> {
        let error = |r: &str| Error::bad_request("Protocol.validate_self", r);
        if self.channel.is_some() != self.permissions.channel.is_some() {
            return Err(error("Channel permission present with out channel protocol"));
        }
        if !self.delete && self.permissions.can_delete {
            return Err(error("Delete Permission Required while deletese are disabled"));
        }
        Ok(())
    }

    pub fn validate_payload(&self, payload: &[u8]) -> Result<(), Error> {
        let error = |r: &str| Error::bad_request("Protocol.validate_payload", r);
        if let Some(schema) = self.schema.as_ref() {
            JSONSchema::compile(&serde_json::from_str(schema)?)
            .map_err(|e| error(&format!("schema failed to compile: {:?}", e)))?
            .validate(&serde_json::from_slice(payload)?)
            .map_err(|e| error(&format!(
                "schema failed for payload: {:?}",
                e.map(|e| e.to_string()).collect::<Vec<String>>()
            )))?;
        } else if !payload.is_empty() {
            return Err(error("Payload was not empty"));
        }
        Ok(())
    }
}
