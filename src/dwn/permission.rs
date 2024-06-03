use super::Error;

use crate::common::structs::Either;

use crate::crypto::secp256k1::{SecretKey, PublicKey, Key};

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
    pub fn new(
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
    pub fn new(can_discover: bool, can_create: bool, can_read: bool) -> Self {
        ChannelPermissionOptions{can_discover, can_create, can_read}
    }
}

#[derive(JsonSchema, Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ChannelPermission {
    pub discover: Key,
    pub create: Key,
    pub read: Key,
    pub delete: PublicKey,//Key provided so that records that require a delete key that are created under a channel can use a known key(Combine discover key for child with this key and XOR some constant to prevent anyone from using this key ever)
}

impl ChannelPermission {
    pub fn validate(&self, other: &Self) -> Result<(), Error> {
        let error = |r: &str| Error::bad_request("ChannelPermission.validate", r);
        if self.discover.map_ref_to_left(|k| k.public_key()) !=
            other.discover.map_ref_to_left(|k| k.public_key())  {
            return Err(error("DiscoverChild key does not match"));
        }
        if self.create.map_ref_to_left(|k| k.public_key()) !=
            other.create.map_ref_to_left(|k| k.public_key()) {
            return Err(error("CreateChild key does not match"));
        }
        if self.read.map_ref_to_left(|k| k.public_key()) !=
            other.read.map_ref_to_left(|k| k.public_key()) {
            return Err(error("ReadChild key dose not match"));
        }
        if self.delete != other.delete {
            return Err(error("DeleteChild key dose not match"));
        }
        Ok(())
    }
}

#[derive(JsonSchema, Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Permission {
    pub discover: SecretKey,
    pub create: Key,
    pub read: Key,
    pub delete: Option<Key>,
    pub channel: Option<ChannelPermission>
}

impl Permission {
    pub fn new(
        discover: SecretKey,
        create: Key,
        read: Key,
        delete: Option<Key>,
        channel: Option<ChannelPermission>
    ) -> Permission {
        Permission{discover, create, read, delete, channel}
    }

    pub fn from_key(key: &SecretKey) -> Result<Permission, Error> {
        Ok(Permission{
            discover: key.derive_usize(0)?,
            create: Either::Right(key.derive_usize(1)?),
            read: Either::Right(key.derive_usize(2)?),
            delete: Some(Either::Right(key.derive_usize(3)?)),
            channel: Some(ChannelPermission{
                discover: Either::Right(key.derive_usize(4)?),
                create: Either::Right(key.derive_usize(5)?),
                read: Either::Right(key.derive_usize(6)?),
                delete: key.derive_usize(7)?.public_key(),
            })
        })
    }

    pub fn subset(self, options: &PermissionOptions) -> Result<Self, Error> {
        let error = |r: &str| Err(Error::bad_request("Permission.subset", r));
        if options.can_create && self.create.is_left() {return error("Missing create permission");}
        if options.can_read && self.read.is_left() {return error("Missing read permission");}
        if options.can_delete && self.delete.as_ref().map(|d| d.is_left()).unwrap_or(true) {return error("Missing delete permission");}
        if options.channel.is_some() && self.channel.is_none() {return error("Missing channel permission");}
        if let Some(options_channel) = &options.channel {
            if let Some(channel) = &self.channel {
                if options_channel.can_discover && channel.discover.is_left() {return error("Missing discover child permission");}
                if options_channel.can_create && channel.create.is_left() {return error("Missing create child permission");}
                if options_channel.can_read && channel.read.is_left() {return error("Missing read child permission");}
            }
        }
        Ok(Permission{
            discover: self.discover,
            create: if options.can_create {self.create} else {Either::Left(self.create.map_to_left(|k| k.public_key()))},
            read: if options.can_read {self.read} else {Either::Left(self.read.map_to_left(|k| k.public_key()))},
            delete: if options.can_delete {self.delete} else {self.delete.map(|d| Either::Left(d.map_to_left(|k| k.public_key())))},
            channel: options.channel.as_ref().map(|c| {
                let channel = self.channel.unwrap();
                ChannelPermission{
                    discover: if c.can_discover {channel.discover} else {Either::Left(channel.discover.map_to_left(|k| k.public_key()))},
                    create: if c.can_create {channel.create} else {Either::Left(channel.create.map_to_left(|k| k.public_key()))},
                    read: if c.can_read {channel.read} else {Either::Left(channel.read.map_to_left(|k| k.public_key()))},
                    delete: channel.delete
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
        Ok(Permission{
            discover: self.discover,
            create: self.create.right_or(other.create),
            read: self.read.right_or(other.read),
            delete: self.delete.map(|d| d.right_or(other.delete.unwrap())),
            channel: self.channel.map(|channel| {
                let other_channel = other.channel.unwrap();
                ChannelPermission{
                    discover: channel.discover.right_or(other_channel.discover),
                    create: channel.create.right_or(other_channel.create),
                    read: channel.read.right_or(other_channel.read),
                    delete: channel.delete,
                }
            })
        })
    }

    pub fn validate(&self, other: &Self) -> Result<(), Error> {
        let error = |r: &str| Error::bad_request("Permission.validate", r);
        if self.discover != other.discover {
            return Err(error("Discover key dose not match"));
        }
        if self.create.map_ref_to_left(|k| k.public_key()) !=
            other.create.map_ref_to_left(|k| k.public_key()) {
            return Err(error("Create key dose not match"));
        }
        if self.read.map_ref_to_left(|k| k.public_key()) !=
            other.read.map_ref_to_left(|k| k.public_key()) {
            return Err(error("Read key does not match"));
        }
        if self.delete.as_ref().map(|d| d.map_ref_to_left(|r| r.public_key())) !=
            other.delete.as_ref().map(|d| d.map_ref_to_left(|r| r.public_key())) {
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
