use super::Error;

use super::permission::{
    ChannelPermissionOptions,
    PermissionOptions,
    PermissionSet,
};

use crate::common::Schemas;
use chrono::{DateTime, Utc};

use simple_crypto::{PublicKey, Hashable, Hash};

use std::collections::BTreeMap;

use simple_database::Indexable;

use schemars::{JsonSchema, schema_for};
use serde::{Serialize, Deserialize};

#[derive(JsonSchema, Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ChannelProtocol {
    pub child_protocols: Option<Vec<Hash>>, //None for any child empty for no children
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
        protocol.validate()?;
        Ok(protocol)
    }

    pub fn is_valid_child(&self, child_protocol: &Hash) -> Result<(), Error> {
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

    fn validate(&self) -> Result<(), Error> {
        let error = |r: &str| Error::bad_request("Protocol.validate_self", r);
        if self.channel.is_some() != self.permissions.channel.is_some() {
            return Err(error("Channel permission present with out channel protocol"));
        }
        if !self.delete && self.permissions.can_delete {
            return Err(error("Delete Permission Required while deletese are disabled"));
        }
        Ok(())
    }
}

pub struct SystemProtocols{}
impl SystemProtocols {
    pub fn get_map() -> BTreeMap<Hash, Protocol> {
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

    pub fn root() -> Protocol {
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

    pub fn protocol_folder(protocol: Hash) -> Protocol {
        Protocol::new(
            &format!("protocol_folder: {}", hex::encode(protocol.as_bytes())),
            false,
            PermissionOptions::new(false, false, false, Some(
                ChannelPermissionOptions::new(false, false, false)
            )),
            None,
            Some(ChannelProtocol::new(Some(vec![protocol])))
        ).unwrap()
    }

    pub fn dms_channel() -> Protocol {
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

    pub fn agent_keys() -> Protocol {
        Protocol::new(
            "agent_keys",
            true,
            PermissionOptions::new(true, true, true, None),
            Some(serde_json::to_string(&schema_for!(Vec<PublicKey>)).unwrap()),
            None
        ).unwrap()
    }

    pub fn date_time() -> Protocol {
        Protocol::new(
            "date_time",
            true,
            PermissionOptions::new(true, true, true, None),
            Some(serde_json::to_string(&schema_for!(DateTime<Utc>)).unwrap()),
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
