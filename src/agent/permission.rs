use super::Error;

use simple_crypto::{SecretKey, Key};
use super::structs::RecordPath;

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

    pub fn update() -> Self {
        PermissionOptions{can_create: true, can_read: true, can_delete: true, channel: None}
    }

    pub fn create_child() -> Self {
        PermissionOptions{can_create: false, can_read: false, can_delete: false, channel: Some(ChannelPermissionOptions{can_create: true, can_read: false})}
    }

    pub fn read_child() -> Self {
        PermissionOptions{can_create: false, can_read: false, can_delete: false, channel: Some(ChannelPermissionOptions{can_create: false, can_read: true})}
    }
}

#[derive(JsonSchema, Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ChannelPermissionOptions {
    pub can_create: bool,
    pub can_read: bool,
}

impl ChannelPermissionOptions {
    pub const fn new(can_create: bool, can_read: bool) -> Self {
        ChannelPermissionOptions{can_create, can_read}
    }
}

#[derive(JsonSchema, Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ChannelPermissionSet {
    pub discover: Key,
    pub create: Key,
    pub read: Key,
}

impl ChannelPermissionSet {
    pub const fn new(discover: Key, create: Key, read: Key) -> Self {
        ChannelPermissionSet{discover, create, read}
    }

    pub fn validate(&self, other: &Self) -> Result<(), Error> {
        let error = |r: &str| Error::validation(r);
        if self.discover.public_key() != other.discover.public_key()  {
            return Err(error("Discover Child"));
        }
        if self.create.public_key() != other.create.public_key() {
            return Err(error("Create Child"));
        }
        if self.read.public_key() != other.read.public_key() {
            return Err(error("Read Child"));
        }
        Ok(())
    }
}

#[derive(JsonSchema, Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PermissionSet {
    pub path: RecordPath,
    pub discover: SecretKey,
    pub create: Key,
    pub read: Key,
    pub delete: Option<Key>,
    pub channel: Option<ChannelPermissionSet>
}

impl PermissionSet {
    pub fn new(
        path: RecordPath,
        discover: SecretKey,
        create: Key,
        read: Key,
        delete: Option<Key>,
        channel: Option<ChannelPermissionSet>
    ) -> Self {
        PermissionSet{path, discover, create, read, delete, channel}
    }

    pub fn discover(&self) -> SecretKey {
        self.discover.clone()
    }

    pub fn create(&self) -> Result<SecretKey, Error> {
        self.create.secret_key().ok_or(Error::invalid_auth("Create"))
    }

    pub fn read(&self) -> Result<SecretKey, Error> {
        self.read.secret_key().ok_or(Error::invalid_auth("Read"))
    }

    pub fn delete(&self) -> Result<SecretKey, Error> {
        self.delete.as_ref()
        .ok_or(Error::invalid_auth("Protocol Does Not Support Delete"))?
        .secret_key().ok_or(Error::invalid_auth("Delete"))
    }

    pub fn channel(&self) -> Result<&ChannelPermissionSet, Error> {
        self.channel.as_ref().ok_or(Error::invalid_auth("Channel"))
    }

    pub fn discover_child(&self) -> Result<SecretKey, Error> {
        self.channel()?.discover.secret_key()
        .ok_or(Error::invalid_auth("Discover Child"))
    }

    pub fn create_child(&self) -> Result<SecretKey, Error> {
        self.channel()?.create.secret_key()
        .ok_or(Error::invalid_auth("Create Child"))
    }

    pub fn read_child(&self) -> Result<SecretKey, Error> {
        self.channel()?.read.secret_key()
        .ok_or(Error::invalid_auth("Create Child"))
    }

    pub fn pointer(&self, index: usize) -> Result<Self, Error> {
        Ok(PermissionSet::new(
            RecordPath::new(&[]),
            self.discover_child()?.derive_usize(index)?,
            self.channel()?.create.clone(),
            self.channel()?.read.clone(),
            None, None
        ))
    }

    pub fn subset(self, options: &PermissionOptions) -> Result<Self, Error> {
        let error = |r: &str| Err(Error::bad_request(r));
        if options.can_create && self.create.is_public() {return error("Missing create permission");}
        if options.can_read && self.read.is_public() {return error("Missing read permission");}
        if options.can_delete && self.delete.as_ref().map(|d| d.is_public()).unwrap_or(true) {return error("Missing delete permission");}
        if options.channel.is_some() && self.channel.is_none() {return error("Missing channel permission");}
        if let Some(options_channel) = &options.channel {
            if let Some(channel) = &self.channel {
                if options_channel.can_create && channel.discover.is_public() || channel.create.is_public() {return error("Missing create child permission");}
                if options_channel.can_read && channel.discover.is_public() || channel.read.is_public() {return error("Missing read child permission");}
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
                    discover: if c.can_create || c.can_read {channel.discover} else {channel.discover.to_public()},
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
        let error = |r: &str| Error::validation(&format!("Permission {}", r));
        if self.path != other.path {
            return Err(error("Path"));
        }
        if self.discover != other.discover {
            return Err(error("Discover"));
        }
        if self.create.public_key() != other.create.public_key() {
            return Err(error("Create"));
        }
        if self.read.public_key() != other.read.public_key() {
            return Err(error("Read"));
        }
        if self.delete.as_ref().map(|d| d.public_key()) !=
            other.delete.as_ref().map(|d| d.public_key()) {
            return Err(error("Delete"));
        }
        if let Some(c1) = &self.channel {
            if let Some(c2) = &other.channel {
                c1.validate(c2)?;
            } else {return Err(error("Channel"));}
        } else if other.channel.is_some() {return Err(error("Channel"));}
        Ok(())
    }
}
