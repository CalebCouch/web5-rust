use super::error::Error;

pub mod permission;
pub mod protocol;
pub mod structs;
pub mod traits;

pub mod router;

mod private_client;
use private_client::PrivateClient;
mod public_client;
use public_client::PublicClient;
mod dm_client;
use dm_client::DMClient;

pub mod server;
pub use server::Server;
pub mod agent;
pub use agent::Agent;
pub mod wallet;
pub use wallet::Wallet;

pub mod json_rpc;
