use super::Error;

use super::structs::PermissionedRecord;
use super::permission::{
    ChannelPermissionOptions,
    PermissionOptions,
    PermissionSet,
};

use crate::common::{Schemas, DateTime};

use simple_crypto::{PublicKey, Hashable, Hash};

use std::collections::BTreeMap;

use simple_database::Indexable;

use schemars::{JsonSchema, schema_for};
use jsonschema::JSONSchema;
use serde::{Serialize, Deserialize};

#[derive(JsonSchema, Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ChannelProtocol {
    pub child_protocols: Option<Vec<Hash>>, //None for any child empty for no children
    //pub delete: bool, //Weather child items can be deleted
}
impl ChannelProtocol {
    pub fn new(child_protocols: Option<Vec<Hash>>) -> Self {
        ChannelProtocol{child_protocols}
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
        protocol.validate_self()?;
        Ok(protocol)
    }

    pub fn system_protocols() -> BTreeMap<Hash, Protocol> {
        let dm = Self::dms_channel();
        let ak = Self::agent_keys();
        let dt = Self::date_time();
        let us = Self::usize();
        let ci = Self::channel_item();
        let sp = Self::shared_pointer();
        let pp = Self::perm_pointer();
        let p = Self::pointer();
        let r = Self::root();
        BTreeMap::from([
            (dm.hash(), dm),
            (ak.hash(), ak),
            (dt.hash(), dt),
            (us.hash(), us),
            (ci.hash(), ci),
            (sp.hash(), sp),
            (pp.hash(), pp),
            (p.hash(), p),
            (r.hash(), r),
        ])
    }

    pub fn root() -> Self {
        Protocol::new(
            "root",
            false,
            PermissionOptions::new(true, true, false, Some(
                ChannelPermissionOptions::new(true, true, true)
            )),
            None,
            Some(ChannelProtocol::new(None))
        ).unwrap()
    }

    pub fn protocol_folder(protocol: &Hash) -> Self {
        Protocol::new(
            &format!("protocol_folder: {}", hex::encode(protocol.as_bytes())),
            false,
            PermissionOptions::new(false, false, false, Some(
                ChannelPermissionOptions::new(false, false, false)
            )),
            None,
            Some(ChannelProtocol::new(Some(vec![*protocol])))
        ).unwrap()
    }

    pub fn dms_channel() -> Self {
        Protocol::new(
            "dms_channel",
            true,
            PermissionOptions::new(true, true, true, Some(
                ChannelPermissionOptions::new(true, true, true)
            )),
            None,
            //Some(ChannelProtocol::new(Some(vec![Self::pointer().hash()])))
            Some(ChannelProtocol::new(None))
        ).unwrap()
    }

    pub fn agent_keys() -> Self {
        Protocol::new(
            "agent_keys",
            true,
            PermissionOptions::new(true, true, true, None),
            Some(serde_json::to_string(&schema_for!(Vec<PublicKey>)).unwrap()),
            None
        ).unwrap()
    }

  //pub fn protocols() -> Self {
  //    Protocol::new(
  //        "protocol",
  //        true,
  //        PermissionOptions::new(false, true, false, None),
  //        Some(serde_json::to_string(&schema_for!(Protocol)).unwrap()),
  //        None
  //    ).unwrap()
  //}

    pub fn date_time() -> Self {
        Protocol::new(
            "date_time",
            true,
            PermissionOptions::new(true, true, true, None),
            Some(serde_json::to_string(&schema_for!(DateTime)).unwrap()),
            None
        ).unwrap()
    }

    pub fn usize() -> Self {
        Protocol::new(
            "date_time",
            true,
            PermissionOptions::new(true, true, true, None),
            Some(serde_json::to_string(&schema_for!(usize)).unwrap()),
            None
        ).unwrap()
    }

    pub fn channel_item() -> Self {
        Protocol::new(
            "channel_item",
            false,
            PermissionOptions::new(false, false, false, None),
            Some(serde_json::to_string(&Schemas::any()).unwrap()),
            None
        ).unwrap()
    }

    pub fn perm_pointer() -> Self {
        Protocol::new(
            "perm_pointer",
            false,
            PermissionOptions::new(true, true, false, None),
            Some(serde_json::to_string(&schema_for!(PermissionSet)).unwrap()),
            None
        ).unwrap()
    }

    pub fn pointer() -> Self {
        Protocol::new(
            "pointer",
            true,
            PermissionOptions::new(true, true, true, None),
            Some(serde_json::to_string(&schema_for!(PermissionSet)).unwrap()),
            None
        ).unwrap()
    }

    pub fn shared_pointer() -> Self {
        Protocol::new(
            "shared_pointer",
            false,
            PermissionOptions::new(true, true, false, None),
            Some(serde_json::to_string(&schema_for!(Vec<Vec<u8>>)).unwrap()),
            None
        ).unwrap()
    }

    pub fn trim_perms(&self, mut perms: PermissionSet) -> PermissionSet {
        if !self.delete {perms.delete = None;}
        if self.channel.is_none() {perms.channel = None;}
        perms
    }

    pub fn subset_perms(&self, perms: &PermissionSet) -> Result<PermissionSet, Error> {
        Ok(self.trim_perms(perms.clone().subset(&self.permissions)?))
    }

    pub fn validate_child_protocol(&self, child_protocol: &Hash) -> Result<(), Error> {
        let error = |r: &str| Error::bad_request("Protocol.validate_child_protocol", r);
        if let Some(channel) = &self.channel {
            if let Some(cps) = &channel.child_protocols {
                if !cps.contains(child_protocol) {
                    return Err(error("ChildProtocol not supported by channel"));
                }
            }
            Ok(())
        } else {Err(error("Protocol Has No Channel"))}
    }

    pub fn validate_child(&self, perm_record: &PermissionedRecord) -> Result<(), Error> {
        self.validate_child_protocol(&perm_record.1.protocol)
    }

    pub fn validate(&self, permissioned_record: &PermissionedRecord) -> Result<(), Error> {
        let error = |r: &str| Error::bad_request("Protocol.validate", r);
        let (perms, record) = permissioned_record;
        self.validate_self()?;
        self.subset_perms(perms).or(Err(error(
            "Permission could not meet minimum permission requirements"
        )))?;
        if *perms != self.trim_perms(perms.clone()) {
            return Err(error("Permission contained a delete key or channel keys which are unsupported by this protocol"));
        }
        if self.hash() != record.protocol {
            return Err(error("Record does not use this protocol"));
        }
        self.validate_payload(&record.payload)?;
      //if if let Some(c) = &self.channel {!c.delete} else {true} && !record.channel_deletes.is_empty() {
      //    return Err(error("Record contains delete child elements but deletes are not enabled"));
      //}
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
