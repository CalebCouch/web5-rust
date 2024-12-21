use super::Error;

use super::permission::{
    ChannelPermissionOptions,
    PermissionOptions,
    PermissionSet,
};
use super::structs::RecordPath;

use crate::common::Schemas;

use std::collections::BTreeMap;

use simple_crypto::{PublicKey, Hashable};

use simple_database::Indexable;

use schemars::{JsonSchema, schema_for};
use serde::{Serialize, Deserialize};
use uuid::Uuid;


use jsonschema::JSONSchema;

#[derive(JsonSchema, Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ChannelProtocol {
    pub child_protocols: Option<Vec<Uuid>>, //None for any child empty for no children
}
impl ChannelProtocol {
    pub fn new(child_protocols: Option<Vec<&Protocol>>) -> Self {
        ChannelProtocol{child_protocols: child_protocols.map(|cp| cp.into_iter().map(|p| p.uuid()).collect())}
    }
}

#[derive(JsonSchema, Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Protocol {
    pub name: String,
    pub delete: bool,//Weather record can be deleted
    pub permissions: PermissionOptions,
    pub schema: Option<String>,
    pub channel: Option<ChannelProtocol>
}
impl Hashable for Protocol {}
impl Indexable for Protocol {
    fn primary_key(&self) -> Vec<u8> {self.hash_bytes()}
}
impl Protocol {
    pub fn new(
        name: &str,
        delete: bool,//Weather record can be deleted
        permissions: PermissionOptions,
        schema: Option<String>,
        channel: Option<ChannelProtocol>
    ) -> Result<Self, Error> {
        let protocol = Protocol{name: name.to_string(), delete, permissions, schema, channel};
        protocol.validate()?;
        Ok(protocol)
    }

    pub fn uuid(&self) -> Uuid {
        Uuid::new_v5(&Uuid::NAMESPACE_OID, &self.hash_bytes())
    }

    pub fn trim_permission(&self, mut permission: PermissionSet) -> PermissionSet {
        if !self.delete {permission.delete = None;}
        if self.channel.is_none() {permission.channel = None;}
        permission
    }

    pub fn subset_permission(
        &self, permission: PermissionSet, permission_options: Option<&PermissionOptions>
    ) -> Result<PermissionSet, Error> {
        let options = permission_options.unwrap_or(&self.permissions);
        let perms = self.trim_permission(permission).subset(options)?;
        self.validate_permission(&perms)?;
        Ok(perms)
    }

    pub fn validate_child(&self, child_protocol: &Uuid) -> Result<(), Error> {
        if let Some(channel) = &self.channel {
            if let Some(cps) = &channel.child_protocols {
                if !cps.contains(child_protocol) {
                    return Err(Error::validation("Invalid Child Protocol"));
                }
            }
            Ok(())
        } else {Err(Error::validation("No Channel For Protocol"))}
    }

    fn validate(&self) -> Result<(), Error> {
        if self.channel.is_some() != self.permissions.channel.is_some() {
            return Err(Error::validation("Channel Permission Without Channel Protocol"));
        }
        if !self.delete && self.permissions.can_delete {
            return Err(Error::validation("Deletes Permission Without Deletes Enabled"));
        }
        Ok(())
    }

    pub fn validate_payload(&self, payload: &[u8]) -> Result<(), Error> {
        if let Some(schema) = self.schema.as_ref() {
            JSONSchema::compile(&serde_json::from_str(schema)?)
            .map_err(|_| Error::validation("Invalid Schema"))?
            .validate(&serde_json::from_slice(payload)?)
            .map_err(|_| Error::validation("Invalid Payload"))
        } else if !payload.is_empty() {
            Err(Error::validation("Invalid Payload"))
        } else {Ok(())}
    }

    pub fn validate_permission(&self, perms: &PermissionSet) -> Result<(), Error> {
        let trimmed = self.trim_permission(perms.clone());
        if trimmed != *perms {return Err(Error::validation("Protocol Restrictions Mismatch"));}
        trimmed.subset(&self.permissions).or(Err(Error::validation("Insuffcient Permission")))?;
        Ok(())
    }
}

pub struct SystemProtocols{}
impl SystemProtocols {
    pub fn all() -> Vec<Protocol> {
        vec![
            Self::dms_channel(),
            Self::agent_keys(),
            //Self::date_time(),
            Self::usize(),
            Self::channel_item(),
            Self::shared_pointer(),
            Self::perm_pointer(),
            Self::pointer(),
            Self::root(),
        ]
    }

    pub fn root() -> Protocol {
        Protocol::new(
            "root",
            false,
            PermissionOptions::new(true, true, false, Some(
                ChannelPermissionOptions::new(true, true)
            )),
            None,
            Some(ChannelProtocol::new(None))
        ).unwrap()
    }

    pub fn protocol_folder(protocol: Uuid) -> Protocol {
        Protocol::new(
            &format!("protocol_folder: {}", hex::encode(protocol.as_bytes())),
            false,
            PermissionOptions::new(false, false, false, Some(
                ChannelPermissionOptions::new(false, false)
            )),
            None,
            Some(ChannelProtocol{child_protocols: Some(vec![protocol])})
        ).unwrap()
    }

    pub fn dms_channel() -> Protocol {
        Protocol::new(
            "dms_channel",
            true,
            PermissionOptions::new(true, true, true, Some(
                ChannelPermissionOptions::new(true, true)
            )),
            None,
            Some(ChannelProtocol::new(None))
        ).unwrap()
    }

    pub fn agent_keys() -> Protocol {
        Protocol::new(
            "agent_keys",
            true,
            PermissionOptions::new(true, true, true, None),
            Some(serde_json::to_string(&schema_for!(BTreeMap<RecordPath, PublicKey>)).unwrap()),
            None
        ).unwrap()
    }

    pub fn usize() -> Protocol {
        Protocol::new(
            "date_time",
            true,
            PermissionOptions::new(true, true, true, None),
            Some(serde_json::to_string(&schema_for!(usize)).unwrap()),
            None
        ).unwrap()
    }

    pub fn channel_item() -> Protocol {
        Protocol::new(
            "channel_item",
            false,
            PermissionOptions::new(false, false, false, None),
            Some(serde_json::to_string(&Schemas::any()).unwrap()),
            None
        ).unwrap()
    }

    pub fn perm_pointer() -> Protocol {
        Protocol::new(
            "perm_pointer",
            false,
            PermissionOptions::new(true, true, false, None),
            Some(serde_json::to_string(&schema_for!(PermissionSet)).unwrap()),
            None
        ).unwrap()
    }

    pub fn pointer() -> Protocol {
        Protocol::new(
            "pointer",
            true,
            PermissionOptions::new(true, true, true, None),
            Some(serde_json::to_string(&schema_for!(PermissionSet)).unwrap()),
            None
        ).unwrap()
    }

    pub fn shared_pointer() -> Protocol {
        Protocol::new(
            "shared_pointer",
            false,
            PermissionOptions::new(true, true, false, None),
            Some(serde_json::to_string(&schema_for!(Vec<Vec<u8>>)).unwrap()),
            None
        ).unwrap()
    }
}
