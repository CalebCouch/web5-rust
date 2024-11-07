mod common;
mod ed25519;
pub mod dids;
mod dwn;
mod error;

pub use dwn::{Wallet, Agent, Server};
pub use dwn::permission::{ChannelPermissionOptions, PermissionOptions};
pub use dwn::protocol::{ChannelProtocol, Protocol};
pub use dwn::structs::Record;
pub use dwn::traits::Router;
pub use error::Error;

pub extern crate simple_database;

#[cfg(test)]
mod tests;

