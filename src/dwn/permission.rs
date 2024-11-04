use super::Error;

use simple_crypto::{SecretKey, Hash, Key};

use super::structs::DwnKey;
use super::protocol::Protocol;

use schemars::JsonSchema;
use serde::{Serialize, Deserialize};

#[derive(JsonSchema, Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PermissionOptions {
    pub can_create: bool,
    pub can_read: bool,
    pub can_delete: bool,
    pub channel: Option<ChannelPermissionOptions>
}

impl PermissionOptions {
    pub const fn new(
        can_create: bool, can_read: bool, can_delete: bool,
        channel: Option<ChannelPermissionOptions>
    ) -> Self {
        PermissionOptions{can_create, can_read, can_delete, channel}
    }
}

#[derive(JsonSchema, Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ChannelPermissionOptions {
    pub can_discover: bool,
    pub can_create: bool,
    pub can_read: bool,
}

impl ChannelPermissionOptions {
    pub const fn new(can_discover: bool, can_create: bool, can_read: bool) -> Self {
        ChannelPermissionOptions{can_discover, can_create, can_read}
    }
}

#[derive(JsonSchema, Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ChannelPermissionSet {
    pub discover: Key,
    pub create: Key,
    pub read: Key,
}

impl ChannelPermissionSet {
    pub fn validate(&self, other: &Self) -> Result<(), Error> {
        let error = |r: &str| Error::bad_request("ChannelPermission.validate", r);
        if self.discover.public_key() != other.discover.public_key()  {
            return Err(error("DiscoverChild key does not match"));
        }
        if self.create.public_key() != other.create.public_key() {
            return Err(error("CreateChild key does not match"));
        }
        if self.read.public_key() != other.read.public_key() {
            return Err(error("ReadChild key dose not match"));
        }
        Ok(())
    }
}

#[derive(JsonSchema, Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PermissionSet {
    pub path: Vec<Hash>,
    pub discover: SecretKey,
    pub create: Key,
    pub read: Key,
    pub delete: Option<Key>,
    pub channel: Option<ChannelPermissionSet>
}

impl PermissionSet {
    pub fn new(
        path: Vec<Hash>,
        discover: SecretKey,
        create: Key,
        read: Key,
        delete: Option<Key>,
        channel: Option<ChannelPermissionSet>
    ) -> Self {
        PermissionSet{path, discover, create, read, delete, channel}
    }

    pub fn from_key(key: &DwnKey) -> Result<PermissionSet, Error> {
        let path = key.path.clone();
        let key = &key.key;
        Ok(PermissionSet{
            path,
            discover: key.derive_usize(0)?,
            create: Key::new_secret(key.derive_usize(1)?),
            read: Key::new_secret(key.derive_usize(2)?),
            delete: Some(Key::new_secret(key.derive_usize(3)?)),
            channel: Some(ChannelPermissionSet{
                discover: Key::new_secret(key.derive_usize(4)?),
                create: Key::new_secret(key.derive_usize(5)?),
                read: Key::new_secret(key.derive_usize(6)?),
            })
        })
    }

    pub fn trim(mut self, protocol: &Protocol) -> Self {
        if !protocol.delete {self.delete = None;}
        if protocol.channel.is_none() {self.channel = None;}
        self
    }

    pub fn get_min_perms(self, protocol: &Protocol) -> Result<PermissionSet, Error> {
        self.trim(protocol).subset(&protocol.permissions)
    }

    pub fn subset(self, options: &PermissionOptions) -> Result<Self, Error> {
        let error = |r: &str| Err(Error::bad_request("Permission.subset", r));
        if options.can_create && self.create.is_public() {return error("Missing create permission");}
        if options.can_read && self.read.is_public() {return error("Missing read permission");}
        if options.can_delete && self.delete.as_ref().map(|d| d.is_public()).unwrap_or(true) {return error("Missing delete permission");}
        if options.channel.is_some() && self.channel.is_none() {return error("Missing channel permission");}
        if let Some(options_channel) = &options.channel {
            if let Some(channel) = &self.channel {
                if options_channel.can_discover && channel.discover.is_public() {return error("Missing discover child permission");}
                if options_channel.can_create && channel.create.is_public() {return error("Missing create child permission");}
                if options_channel.can_read && channel.read.is_public() {return error("Missing read child permission");}
            }
        }
        Ok(PermissionSet{
            path: self.path,
            discover: self.discover,
            create: if options.can_create {self.create} else {self.create.to_public()},
            read: if options.can_read {self.read} else {self.read.to_public()},
            delete: if options.can_delete {self.delete} else {self.delete.map(|d| d.to_public())},
            channel: options.channel.as_ref().map(|c| {
                let channel = self.channel.unwrap();
                ChannelPermissionSet{
                    discover: if c.can_discover {channel.discover} else {channel.discover.to_public()},
                    create: if c.can_create {channel.create} else {channel.create.to_public()},
                    read: if c.can_read {channel.read} else {channel.read.to_public()},
                }
            })
        })
    }

    pub fn combine(mut self, mut other: Self) -> Result<Self, Error> {
        //Assume one of the permissions is raw and contains more then allowed perms
        if self.delete.is_none() {other.delete = None;}
        else if other.delete.is_none() {self.delete = None;}
        if self.channel.is_none() {other.channel = None;}
        else if other.channel.is_none() {self.channel = None;}
        self.validate(&other)?;
        Ok(PermissionSet{
            path: self.path,
            discover: self.discover,
            create: self.create.secret_or(other.create),
            read: self.read.secret_or(other.read),
            delete: self.delete.map(|d| d.secret_or(other.delete.unwrap())),
            channel: self.channel.map(|channel| {
                let other_channel = other.channel.unwrap();
                ChannelPermissionSet{
                    discover: channel.discover.secret_or(other_channel.discover),
                    create: channel.create.secret_or(other_channel.create),
                    read: channel.read.secret_or(other_channel.read),
                }
            })
        })
    }

    pub fn validate(&self, other: &Self) -> Result<(), Error> {
        let error = |r: &str| Error::bad_request("Permission.validate", r);
        if self.path != other.path {
            return Err(error("Record paths do not match"));
        }
        if self.discover != other.discover {
            return Err(error("Discover key dose not match"));
        }
        if self.create.public_key() != other.create.public_key() {
            return Err(error("Create key dose not match"));
        }
        if self.read.public_key() != other.read.public_key() {
            return Err(error("Read key does not match"));
        }
        if self.delete.as_ref().map(|d| d.public_key()) !=
            other.delete.as_ref().map(|d| d.public_key()) {
            return Err(error("Delete key dose not match"));
        }
        if let Some(c1) = &self.channel {
            if let Some(c2) = &other.channel {
                c1.validate(c2)?;
            } else {return Err(error("Channel presence does not match"));}
        } else if other.channel.is_some() {return Err(error("Channel presence does not match"));}
        Ok(())
    }
}
