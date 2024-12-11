mod error;
pub use error::Error;

mod common;
mod ed25519;
pub mod dids;


mod dwn;
pub use dwn::{DwnIdentity, Dwn};
pub use dwn::traits::{Client, Server};
pub use dwn::router::Router;
pub use dwn::json_rpc::{JsonRpcClient, JsonRpcServer};
pub use dwn::structs::PublicRecord;

mod agent;
pub use agent::scripts;
pub use agent::commands;
pub use agent::{Agent, Wallet, Identity, AgentKey};
pub use agent::permission::{PermissionOptions, ChannelPermissionOptions};
pub use agent::protocol::{Protocol, ChannelProtocol};

pub extern crate simple_database;

#[cfg(test)]
mod tests;

